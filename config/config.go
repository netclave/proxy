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

package config

import (
	"bufio"
	"flag"
	"log"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/netclave/common/storage"
)

var DataStorageCredentials map[string]string
var StorageType string

var Fail2BanDataStorageCredentials map[string]string
var Fail2BanStorageType string
var Fail2BanTTL int64

var TokenTTL = time.Duration(300)

var ListenProxyAddress = ":9998"
var ListenGRPCAddress = "localhost:6664"
var ProxyRules map[string][]map[string]string

func Init() error {
	ProxyRules = map[string][]map[string]string{}

	flag.String("configFile", "/opt/config.json", "Provide full path to your config json file")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	filename := viper.GetString("configFile") // retrieve value from viper

	file, err := os.Open(filename)

	viper.SetConfigType("json")

	if err != nil {
		log.Println(err.Error())
	} else {
		err = viper.ReadConfig(bufio.NewReader(file))

		if err != nil {
			log.Println(err.Error())
			return err
		}
	}

	viper.SetDefault("host.httpaddress", ":9998")
	viper.SetDefault("host.grpcaddress", "localhost:6664")

	viper.SetDefault("datastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "4",
		"password": "",
	})
	viper.SetDefault("datastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("fail2bandatastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "5",
		"password": "",
	})
	viper.SetDefault("fail2bandatastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("fail2banttl", int64(300000))

	hostConfig := viper.Sub("host")

	ListenProxyAddress = hostConfig.GetString("httpaddress")
	ListenGRPCAddress = hostConfig.GetString("grpcaddress")

	log.Println(ListenProxyAddress)
	log.Println(ListenGRPCAddress)

	datastorageConfig := viper.Sub("datastorage")

	DataStorageCredentials = datastorageConfig.GetStringMapString("credentials")
	StorageType = datastorageConfig.GetString("type")

	fail2banDatastorageConfig := viper.Sub("fail2bandatastorage")

	Fail2BanDataStorageCredentials = fail2banDatastorageConfig.GetStringMapString("credentials")
	Fail2BanStorageType = fail2banDatastorageConfig.GetString("type")

	Fail2BanTTL = viper.GetInt64("fail2banttl")

	hostsKeys := viper.GetStringMap("rules")

	for hostKey := range hostsKeys {
		log.Println(hostKey)

		var rules []map[string]string

		err = viper.UnmarshalKey("rules."+hostKey, &rules)

		if err != nil {
			log.Println(err.Error())
			return err
		}

		ProxyRules[hostKey] = rules

		for _, rule := range rules {
			for from, to := range rule {
				log.Println(hostKey + from + " ---> " + to)
			}
		}
	}

	return nil
}
