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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"time"

	api "github.com/netclave/apis/proxy/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/proxy/component"
	"github.com/netclave/proxy/config"
	"github.com/netclave/proxy/handlers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func startGRPCServer(address string) error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// create a listener on TCP port
	lis, err := net.Listen("tcp", address)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	// create a server instance
	s := handlers.GrpcServer{}

	ServerMaxReceiveMessageSize := math.MaxInt32

	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(ServerMaxReceiveMessageSize)}
	// create a gRPC server object
	grpcServer := grpc.NewServer(opts...)

	// attach the Ping service to the server
	api.RegisterProxyAdminServer(grpcServer, &s)

	// start the server
	log.Printf("starting HTTP/2 gRPC server on %s", address)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %s", err)
	}

	return nil
}

func startWalletsAndServicesDaemon() error {

	for {
		walletsAndServices, err := handlers.GetWalletsAndServiceInternal()

		if err != nil {
			log.Println(err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		cryptoStorage := component.CreateCryptoStorage()

		dataStorage := component.CreateDataStorage()

		for key, value := range walletsAndServices.PublicKeys {
			identificator := &cryptoutils.Identificator{
				IdentificatorID:   key,
				IdentificatorType: cryptoutils.IDENTIFICATOR_TYPE_WALLET,
			}

			err := cryptoStorage.AddIdentificator(identificator)

			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}

			err = cryptoStorage.StorePublicKey(key, value)

			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(component.ProxyIdentificator, identificator)

			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}

			err = cryptoStorage.AddIdentificatorToIdentificator(identificator, component.ProxyIdentificator)

			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}

			services, ok := walletsAndServices.Services[key]

			if ok == false {
				continue
			}

			jsonData, err := json.Marshal(services)

			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}

			err = dataStorage.SetKey(component.SERVICES, key, string(jsonData), config.TokenTTL*time.Second)
			if err != nil {
				log.Println(err.Error())
				time.Sleep(2 * time.Second)
				continue
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func startActiveTokensDaemon() error {
	for {
		tokens, err := handlers.GetActiveTokensInternal()

		if err != nil {
			log.Println(err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		dataStorage := component.CreateDataStorage()

		for key, value := range tokens {
			for _, token := range value {
				res, err := dataStorage.GetKey(component.TOKENS, key+"/"+token)

				if err != nil {
					log.Println(err.Error())
					time.Sleep(2 * time.Second)
					continue
				}

				if res == "" {
					err = dataStorage.SetKey(component.TOKENS, key+"/"+token, token, config.TokenTTL*time.Second)
					if err != nil {
						log.Println(err.Error())
						time.Sleep(2 * time.Second)
						continue
					}
				}
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func startProxyServer(bind string, rules map[string][]map[string]string) error {
	srv := &http.Server{}

	h := &handlers.Handle{
		Rules:     rules,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		},
	}

	log.Println("Binding to: " + bind)

	srv.Addr = bind
	srv.Handler = h
	if err := srv.ListenAndServe(); err != nil {
		log.Println("ListenAndServe: " + err.Error())
	}

	return nil
}

func startFail2BanDeamon() error {
	for {
		fail2banDataStorage := component.CreateFail2BanDataStorage()

		err := utils.LogBannedIPs(fail2banDataStorage)

		if err != nil {
			log.Println(err.Error())
			return err
		}

		time.Sleep(2 * time.Second)
	}

	return nil
}

func main() {
	err := component.LoadComponent()
	if err != nil {
		log.Println(err.Error())
		return
	}

	go func() {
		err := startWalletsAndServicesDaemon()

		if err != nil {
			log.Println(err.Error())
		}
	}()

	go func() {
		err := startActiveTokensDaemon()

		if err != nil {
			log.Println(err.Error())
		}
	}()

	go func() {
		err := startProxyServer(config.ListenProxyAddress, config.ProxyRules)

		if err != nil {
			log.Println(err.Error())
		}
	}()

	go func() {
		err := startFail2BanDeamon()

		if err != nil {
			log.Println(err.Error())
		}
	}()

	log.Println("Starting grpc server")
	err = startGRPCServer(config.ListenGRPCAddress)
}
