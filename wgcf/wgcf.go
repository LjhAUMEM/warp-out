package wgcf

import (
	"fmt"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	"github.com/ViRb3/wgcf/v2/cmd/shared"
	"github.com/ViRb3/wgcf/v2/util"
	"github.com/ViRb3/wgcf/v2/wireguard"

	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigFile("wgcf-account.toml")
	viper.ReadInConfig()
}

func Reg() {
	privateKey, _ := wireguard.NewPrivateKey()
	device, _ := cloudflare.Register(privateKey.Public(), "PC")
	viper.Set("private_key", privateKey.String())
	viper.Set("device_id", device.Id)
	viper.Set("access_token", device.Token)
	viper.Set("license_key", device.Account.License)
	viper.WriteConfig()
	ctx := shared.CreateContext()
	cloudflare.UpdateSourceBoundDeviceName(ctx, util.RandomHexString(3))
	cloudflare.UpdateSourceBoundDeviceActive(ctx, true)
}

func Get() (tunV4, tunV6, privateKey, publicKey string) {
	if viper.GetString("private_key") == "" {
		Reg()
	}
	ctx := shared.CreateContext()
	device, err := cloudflare.GetSourceDevice(ctx)
	if err != nil {
		fmt.Println("using default account")
		return "172.16.0.2", "2606:4700:110:8377:d6b:2f2b:50be:81ff", "0ADCTQ59Fncpjq4ZqT6qWA3T5TyBTDY0SBuMc0lQu24=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	}
	cloudflare.UpdateSourceBoundDeviceActive(ctx, true)
	return device.Config.Interface.Addresses.V4, device.Config.Interface.Addresses.V6, viper.GetString("private_key"), device.Config.Peers[0].PublicKey
}
