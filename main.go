package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ViRb3/wgcf/cloudflare"
	"github.com/ViRb3/wgcf/cmd/shared"
	"github.com/ViRb3/wgcf/config"
	"github.com/ViRb3/wgcf/wireguard"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"strconv"
	"strings"
)

var existingLicense string

func main() {
	pflag.StringVarP(&existingLicense, "license", "l", "", "")
	pflag.Parse()
	privateKey, _ := wireguard.NewPrivateKey()

	device, err := cloudflare.Register(privateKey.Public(), "Android")
	if err != nil {
		fmt.Println(err)
		return
	}
	viper.Set(config.PrivateKey, privateKey.String())
	viper.Set(config.DeviceId, device.Id)
	viper.Set(config.AccessToken, device.Token)
	viper.Set(config.LicenseKey, device.Account.License)
	if existingLicense != "" && len(existingLicense) >= 26 {
		viper.Set(config.LicenseKey, existingLicense)
		ctx := shared.CreateContext()
		_, err := cloudflare.UpdateLicenseKey(ctx)
		if err != nil {
			fmt.Println(err)
			return
		}
		thisDevice, _ := cloudflare.GetSourceDevice(ctx)
		device.Id = thisDevice.Id
		device.Account.Id = thisDevice.Account.Id
		device.Account.AccountType = thisDevice.Account.AccountType
		device.Account.License = thisDevice.Account.License
		device.Config.Peers[0].PublicKey = thisDevice.Config.Peers[0].PublicKey
		device.Config.ClientId = thisDevice.Config.ClientId
		device.Config.Interface.Addresses.V4 = thisDevice.Config.Interface.Addresses.V4
		device.Config.Interface.Addresses.V6 = thisDevice.Config.Interface.Addresses.V6
		device.Config.Peers[0].Endpoint.Host = thisDevice.Config.Peers[0].Endpoint.Host

	}
	clientID := device.Config.ClientId
	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		fmt.Println(err)
		return
	}
	hexString := hex.EncodeToString(decoded)
	var decValues []string
	for i := 0; i < len(hexString); i += 2 {
		hexByte := hexString[i : i+2]
		decValue, _ := strconv.ParseInt(hexByte, 16, 64)
		decValues = append(decValues, fmt.Sprintf("%d%d%d", decValue/100, (decValue/10)%10, decValue%10))
	}

	var reserved []int
	for i := 0; i < len(hexString); i += 2 {
		hexByte := hexString[i : i+2]
		decValue, _ := strconv.ParseInt(hexByte, 16, 64)
		reserved = append(reserved, int(decValue))
	}
	v4 := device.Config.Interface.Addresses.V4
	v6 := device.Config.Interface.Addresses.V6

	fmt.Println("device_id:", device.Id)
	fmt.Println("token:", device.Token)
	fmt.Println("account_id:", device.Account.Id)
	fmt.Println("account_type:", device.Account.AccountType)
	fmt.Println("license:", device.Account.License)
	fmt.Println("private_key:", privateKey)
	fmt.Println("public_key:", device.Config.Peers[0].PublicKey)
	fmt.Println("client_id:", clientID)
	fmt.Println("reserved: [", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(reserved)), ", "), "[]"), "]")
	fmt.Println("v4:", v4)
	fmt.Println("v6:", v6)
	fmt.Println("endpoint:", device.Config.Peers[0].Endpoint.Host)
}
