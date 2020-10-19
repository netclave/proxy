/*
 * Copyright @ 2020 - present Blackvisor Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handlers

import (
	"context"
	"encoding/json"
	"log"

	api "github.com/netclave/apis/proxy/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/httputils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/proxy/component"
)

type GrpcServer struct {
}

func (s *GrpcServer) AddIdentityProvider(ctx context.Context, in *api.AddIdentityProviderRequest) (*api.AddIdentityProviderResponse, error) {
	identityProviderURL := in.IdentityProviderUrl
	emailOrPhone := in.EmailOrPhone

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, remoteIdentityProviderID, err := httputils.RemoteGetPublicKey(identityProviderURL, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StoreTempPublicKey(remoteIdentityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/registerPublicKey"

	data := map[string]string{}

	data["identificator"] = emailOrPhone

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, identityProviderID,
		privateKeyPEM, publicKeyPEM, publicKey, true)

	response, remoteIdentityProviderID, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.AddIdentityProviderResponse{}, err
	}

	return &api.AddIdentityProviderResponse{
		Response:           response,
		IdentityProviderId: remoteIdentityProviderID,
	}, nil
}

func (s *GrpcServer) ListIdentityProviders(ctx context.Context, in *api.ListIdentityProvidersRequest) (*api.ListIdentityProvidersResponse, error) {
	cryptoStorage := component.CreateCryptoStorage()

	identityProvidersMap, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.ProxyIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ListIdentityProvidersResponse{}, err
	}

	identityProviders := []*api.IdentityProvider{}

	for _, identityProvider := range identityProvidersMap {
		identityProviderObj := &api.IdentityProvider{
			Url: identityProvider.IdentificatorURL,
			Id:  identityProvider.IdentificatorID,
		}

		identityProviders = append(identityProviders, identityProviderObj)
	}

	return &api.ListIdentityProvidersResponse{
		IdentityProviders: identityProviders,
	}, nil
}

func (s *GrpcServer) ConfirmIdentityProvider(ctx context.Context, in *api.ConfirmIdentityProviderRequest) (*api.ConfirmIdentityProviderResponse, error) {
	identityProviderURL := in.IdentityProviderUrl
	identityProviderID := in.IdentityProviderId
	code := in.ConfirmationCode
	proxyName := in.ProxyName

	cryptoStorage := component.CreateCryptoStorage()

	publicKey, err := cryptoStorage.RetrieveTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	fullURL := identityProviderURL + "/confirmPublicKey"

	data := map[string]string{}

	data["confirmationCode"] = code
	data["identificatorType"] = cryptoutils.IDENTIFICATOR_TYPE_PROXY
	data["identificatorName"] = proxyName

	proxyID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	request, err := jsonutils.SignAndEncryptResponse(data, proxyID,
		privateKeyPEM, publicKeyPEM, publicKey, true)

	response, _, _, err := httputils.MakePostRequest(fullURL, request, true, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	//log.Println("Response: " + response)

	if response != "\"Identificator confirmed\"" {
		log.Println("Do not add identificators")
		return &api.ConfirmIdentityProviderResponse{
			Response: response,
		}, nil
	}

	_, err = cryptoStorage.DeleteTempPublicKey(identityProviderID)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.StorePublicKey(identityProviderID, publicKey)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	identificatorObject := &cryptoutils.Identificator{}
	identificatorObject.IdentificatorID = identityProviderID
	identificatorObject.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER
	identificatorObject.IdentificatorURL = identityProviderURL

	err = cryptoStorage.AddIdentificator(identificatorObject)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(identificatorObject, component.ProxyIdentificator)

	if err != nil {
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(component.ProxyIdentificator, identificatorObject)

	if err != nil {
		log.Println(err.Error())
		log.Println("Error: " + err.Error())
		return &api.ConfirmIdentityProviderResponse{}, err
	}

	return &api.ConfirmIdentityProviderResponse{
		Response: response,
	}, nil
}

type WalletsAndServices struct {
	PublicKeys map[string]string
	Services   map[string][]string
}

func GetWalletsAndServiceInternal() (*WalletsAndServices, error) {
	cryptoStorage := component.CreateCryptoStorage()

	identityProviders, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.ProxyIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		return nil, err
	}

	result := &WalletsAndServices{
		PublicKeys: map[string]string{},
		Services:   map[string][]string{},
	}

	for _, identityProvider := range identityProviders {
		publicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)

		if err != nil {
			return nil, err
		}
		openersURL := identityProvider.IdentificatorURL + "/getWalletsAndServices"

		//log.Println("Url: " + openersURL)

		openerID := component.ComponentIdentificatorID
		privateKeyPEM := component.ComponentPrivateKey
		publicKeyPEM := component.ComponentPublicKey

		request, err := jsonutils.SignAndEncryptResponse("", openerID,
			privateKeyPEM, publicKeyPEM, publicKey, false)

		response, _, _, err := httputils.MakePostRequest(openersURL, request, true, component.ComponentPrivateKey, cryptoStorage)

		if err != nil {
			log.Println("Error: " + err.Error())
			return nil, err
		}

		//log.Println("Response: " + response)

		var res WalletsAndServices

		err = json.Unmarshal([]byte(response), &res)

		if err != nil {
			log.Println("Error: " + err.Error())
			return nil, err
		}

		for key, value := range res.PublicKeys {
			result.PublicKeys[key] = value
			_, ok := result.Services[key]

			if ok == false {
				result.Services[key] = []string{}
			}

			services, ok := res.Services[key]

			if ok == true {
				for _, service := range services {
					result.Services[key] = append(result.Services[key], service)
				}
			}
		}
	}

	return result, nil
}

func (s *GrpcServer) GetWalletsAndServices(ctx context.Context, in *api.GetWalletsAndServicesRequest) (*api.GetWalletsAndServicesResponse, error) {
	result := []string{}

	res, err := GetWalletsAndServiceInternal()

	if err != nil {
		return &api.GetWalletsAndServicesResponse{}, nil
	}

	for key, value := range res.PublicKeys {
		publicKey := value
		services := res.Services[key]

		entry := key + "," + publicKey

		for _, service := range services {
			entry = entry + "," + service
		}

		result = append(result, entry)
	}

	return &api.GetWalletsAndServicesResponse{
		DataForWallet: result,
	}, nil
}

func GetActiveTokensInternal() (map[string][]string, error) {
	cryptoStorage := component.CreateCryptoStorage()

	identityProviders, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.ProxyIdentificator, cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER)

	if err != nil {
		return nil, err
	}

	result := map[string][]string{}

	for _, identityProvider := range identityProviders {
		publicKey, err := cryptoStorage.RetrievePublicKey(identityProvider.IdentificatorID)

		if err != nil {
			return nil, err
		}
		openersURL := identityProvider.IdentificatorURL + "/getActiveTokens"

		//log.Println("Url: " + openersURL)

		openerID := component.ComponentIdentificatorID
		privateKeyPEM := component.ComponentPrivateKey
		publicKeyPEM := component.ComponentPublicKey

		request, err := jsonutils.SignAndEncryptResponse("", openerID,
			privateKeyPEM, publicKeyPEM, publicKey, false)

		response, _, _, err := httputils.MakePostRequest(openersURL, request, true, component.ComponentPrivateKey, cryptoStorage)

		if err != nil {
			log.Println("Error: " + err.Error())
			return nil, err
		}

		//log.Println(response)

		var activeTokensForIdentityProvider map[string][]string

		err = json.Unmarshal([]byte(response), &activeTokensForIdentityProvider)

		if err != nil {
			log.Println("Error: " + err.Error())
			return nil, err
		}

		for key, value := range activeTokensForIdentityProvider {
			_, ok := result[key]

			if ok == false {
				result[key] = []string{}
			}

			for _, token := range value {
				result[key] = append(result[key], token)
			}
		}
	}

	return result, nil
}

func (s *GrpcServer) GetActiveTokens(ctx context.Context, in *api.GetActiveTokensRequest) (*api.GetActiveTokensResponse, error) {
	result := []string{}

	activeTokens, err := GetActiveTokensInternal()

	if err != nil {
		return &api.GetActiveTokensResponse{}, err
	}

	for key, value := range activeTokens {

		entry := key

		for _, token := range value {
			entry = entry + "," + token
		}

		result = append(result, entry)
	}

	return &api.GetActiveTokensResponse{
		DataForWallet: result,
	}, nil
}
