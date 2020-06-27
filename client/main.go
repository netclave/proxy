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

package main

import (
	"context"
	"log"
	"os"
	"time"

	api "github.com/netclave/apis/proxy/api"

	"google.golang.org/grpc"
)

func addIdentityProviderRequest(conn *grpc.ClientConn, identityProviderURL, emailOrPhone string) {
	client := api.NewProxyAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.AddIdentityProviderRequest{
		IdentityProviderUrl: identityProviderURL,
		EmailOrPhone:        emailOrPhone,
	}

	response, err := client.AddIdentityProvider(ctx, in)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(response.Response + " " + response.IdentityProviderId)
}

func confirmIdentityProviderRequest(conn *grpc.ClientConn, identityProviderURL, identificator, code, name string) {
	client := api.NewProxyAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ConfirmIdentityProviderRequest{
		IdentityProviderUrl: identityProviderURL,
		IdentityProviderId:  identificator,
		ConfirmationCode:    code,
		ProxyName:           name,
	}

	response, err := client.ConfirmIdentityProvider(ctx, in)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(response.Response)
}

func listIdentityProvidersRequest(conn *grpc.ClientConn) {
	client := api.NewProxyAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListIdentityProvidersRequest{}

	response, err := client.ListIdentityProviders(ctx, in)

	if err != nil {
		log.Println(err)
		return
	}

	identityProviders := response.IdentityProviders

	for _, identityProvider := range identityProviders {
		log.Println(identityProvider.Url + " " + identityProvider.Id)
	}
}

func getWalletsAndServices(conn *grpc.ClientConn) {
	client := api.NewProxyAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.GetWalletsAndServicesRequest{}

	response, err := client.GetWalletsAndServices(ctx, in)

	if err != nil {
		log.Println(err)
		return
	}

	dataForWallet := response.DataForWallet

	for _, dataRow := range dataForWallet {
		log.Println(dataRow)
	}
}

func getActiveTokens(conn *grpc.ClientConn) {
	client := api.NewProxyAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.GetActiveTokensRequest{}

	response, err := client.GetActiveTokens(ctx, in)

	if err != nil {
		log.Println(err)
		return
	}

	dataForWallet := response.DataForWallet

	for _, dataRow := range dataForWallet {
		log.Println(dataRow)
	}
}

func main() {
	if len(os.Args) == 1 || len(os.Args) == 2 {
		log.Println("client url addIdentityProvider identityProviderUrl emailOrPhone")
		log.Println("client url confirmIdentityProvider identityProviderUrl identityProviderId code proxyName")
		log.Println("client url listIdentityProviders")
		log.Println("client url getWalletsAndServices")
		log.Println("client url getActiveTokens")

		return
	}

	var conn *grpc.ClientConn

	conn, err := grpc.Dial(os.Args[1], grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	switch os.Args[2] {
	case "addIdentityProvider":
		{
			addIdentityProviderRequest(conn, os.Args[3], os.Args[4])
		}
	case "confirmIdentityProvider":
		{
			confirmIdentityProviderRequest(conn, os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		}
	case "listIdentityProviders":
		{
			listIdentityProvidersRequest(conn)
		}
	case "getWalletsAndServices":
		{
			getWalletsAndServices(conn)
		}
	case "getActiveTokens":
		{
			getActiveTokens(conn)
		}
	default:
		{
			log.Println("You have to choose program")
		}
	}
}
