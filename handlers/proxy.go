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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/netclave/proxy/config"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/networkutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/proxy/component"
)

type Handle struct {
	Rules     map[string][]map[string]string
	TLSConfig *tls.Config
	Dialer    *net.Dialer
}

func (hd *Handle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cryptoStorage := component.CreateCryptoStorage()
	dataStorage := component.CreateDataStorage()

	fail2banDataStorage := component.CreateFail2BanDataStorage()

	event, err := utils.CreateSimpleEvent(networkutils.GetRemoteAddress(r))

	if err != nil {
		log.Printf(err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	host := r.Host
	path := r.URL.Path

	log.Println(host + " " + path)

	var chosenHostRules []map[string]string
	ok := false

	for key, value := range hd.Rules {
		re := regexp.MustCompile(key)
		result := re.FindString(host)

		if result != "" {
			chosenHostRules = value
			ok = true
			break
		}
	}

	if ok == false {
		err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
		if err != nil {
			log.Printf(err.Error())
			http.Error(w, err.Error(), 500)
			return
		}

		log.Printf("No rule found")
		http.Error(w, "No rule found", 500)
		return
	}

	proxyURL := ""
	proxyOK := false

	for _, rule := range chosenHostRules {
		for from, to := range rule {
			re := regexp.MustCompile(from)
			result := re.FindString(path)

			if result != "" {
				proxyURL = to
				proxyOK = true
				break
			}
		}

		if proxyOK == true {
			break
		}
	}

	if proxyOK == false {
		err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
		if err != nil {
			log.Printf(err.Error())
			http.Error(w, err.Error(), 500)
			return
		}

		log.Printf("No rule found")
		http.Error(w, "No rule found", 500)
		return
	}

	identificators, err := cryptoStorage.GetIdentificators()

	if err != nil {
		log.Printf(err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	for key, identificator := range identificators {
		log.Println(key + " " + identificator.IdentificatorID + " " + identificator.IdentificatorType + " " + identificator.IdentificatorURL)
	}

	hasValidNetClaveCookie := false

	for k, v := range r.Header {
		if strings.ToLower(k) == "cookie" {
			for _, cookies := range v {
				cookiesTokens := strings.Split(cookies, ";")
				for _, cookie := range cookiesTokens {
					trimmedCookie := strings.Trim(cookie, " ")
					log.Println(trimmedCookie)
					cookieTokens := strings.Split(trimmedCookie, "=")
					cookieValue := ""
					if len(cookieTokens) > 2 {
						for i, token := range cookieTokens {
							if i > 1 {
								cookieValue = cookieValue + "=" + token
							} else {
								if i == 1 {
									cookieValue = cookieValue + token
								}
							}
						}
					} else {
						cookieValue = cookieTokens[1]
					}

					identityProviderID := cookieTokens[0]

					log.Println(identityProviderID)
					log.Println(cookieValue)

					netClaveSuffix := "netclave-token-"

					if !strings.Contains(identityProviderID, netClaveSuffix) {
						continue
					}

					identityProviderID = strings.Replace(identityProviderID, netClaveSuffix, "", -1)

					log.Println(identityProviderID)

					cookieValueTokens := strings.Split(cookieValue, ",")

					if len(cookieValueTokens) != 3 {
						log.Printf("Cookie in wrong format")
						continue
					}

					walletID := cookieValueTokens[0]
					token := cookieValueTokens[1]
					signature := cookieValueTokens[2]

					_, ok := identificators[identityProviderID]

					if ok == false {
						log.Printf("No identity provider found")
						continue
					}

					_, ok = identificators[walletID]

					if ok == false {
						log.Printf("No wallet found")
						continue
					}

					walletPublicKeyPEM, err := cryptoStorage.RetrievePublicKey(walletID)

					if err != nil {
						log.Printf(err.Error())
						continue
					}

					walletPublicKey, err := cryptoutils.ParseRSAPublicKey(walletPublicKeyPEM)

					if err != nil {
						log.Printf(err.Error())
						continue
					}

					log.Println(token + " " + signature)

					verified, err := cryptoutils.Verify(token, signature, walletPublicKey)

					if err != nil {
						log.Printf(err.Error())
						continue
					}

					if verified == false {
						log.Printf("Can not verify")
						continue
					}

					log.Println("After verify")

					servicesJSON, err := dataStorage.GetKey(component.SERVICES, walletID)
					if err != nil {
						err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
						if err != nil {
							log.Printf(err.Error())
							http.Error(w, err.Error(), 500)
							return
						}

						log.Printf(err.Error())
						http.Error(w, err.Error(), 500)
						return
					}

					log.Println(servicesJSON)

					var services []string
					err = json.Unmarshal([]byte(servicesJSON), &services)

					if err != nil {
						log.Printf(err.Error())
						continue
					}

					okService := false

					for _, service := range services {
						log.Println(service)
						re := regexp.MustCompile(service)
						result := re.FindString(host)

						if result != "" {
							okService = true
							break
						}
					}

					if okService == false {
						log.Printf("No access")
						continue
					}

					tokenStorage, err := dataStorage.GetKey(component.TOKENS, walletID+"/"+token)
					if err != nil {
						log.Printf(err.Error())
						continue
					}

					if tokenStorage == "" {
						continue
					}

					hasValidNetClaveCookie = true
					break
				}
			}
		}
	}

	if hasValidNetClaveCookie == false {
		err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
		if err != nil {
			log.Printf(err.Error())
			http.Error(w, err.Error(), 500)
			return
		}

		log.Printf("No access")
		http.Error(w, "No access", 500)
		return
	}

	hj, isHJ := w.(http.Hijacker)
	if r.Header.Get("Upgrade") == "websocket" && isHJ {
		c, br, err := hj.Hijack()
		if err != nil {
			err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
			if err != nil {
				log.Printf(err.Error())
				http.Error(w, err.Error(), 500)
				return
			}

			log.Printf("websocket websocket hijack: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		defer c.Close()

		var be net.Conn

		withoutProtocol := strings.Replace(proxyURL, "http://", "", -1)
		withoutProtocol = strings.Replace(withoutProtocol, "https://", "", -1)

		if strings.Contains(proxyURL, "https") {
			be, err = tls.DialWithDialer(hd.Dialer, "tcp", withoutProtocol, hd.TLSConfig)
		} else {
			be, err = net.DialTimeout("tcp", withoutProtocol, 30*time.Second)
		}
		if err != nil {
			err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
			if err != nil {
				log.Printf(err.Error())
				http.Error(w, err.Error(), 500)
				return
			}

			log.Printf("websocket Dial: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		defer be.Close()
		if err := r.Write(be); err != nil {
			err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
			if err != nil {
				log.Printf(err.Error())
				http.Error(w, err.Error(), 500)
				return
			}

			log.Printf("websocket backend write request: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		errc := make(chan error, 1)
		go func() {
			n, err := io.Copy(be, br) // backend <- buffered reader
			if err != nil {
				err = fmt.Errorf("websocket: to copy backend from buffered reader: %v, %v", n, err)
			}
			errc <- err
		}()
		go func() {
			n, err := io.Copy(c, be) // raw conn <- backend
			if err != nil {
				err = fmt.Errorf("websocket: to raw conn from backend: %v, %v", n, err)
			}
			errc <- err
		}()
		if err := <-errc; err != nil {
			log.Print(err)
		}
		return
	}

	log.Println(r.Method)

	url, err := url.Parse(proxyURL)
	if err != nil {
		err = utils.StoreBannedIP(fail2banDataStorage, event, config.Fail2BanTTL)
		if err != nil {
			log.Printf(err.Error())
			http.Error(w, err.Error(), 500)
			return
		}

		log.Printf("Can not parse url: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = url.Host
	proxy.ServeHTTP(w, r)
}
