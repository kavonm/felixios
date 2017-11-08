package main

import (
	//initialize the redis and mysql connection
	_ "github.com/dejavuzhou/felixios/models"
	"github.com/dejavuzhou/felixios/routers"
	"github.com/gin-gonic/autotls"
	"log"
)

func main() {
	log.Fatal(autotls.Run(routers.RouterMap, "captcha.mojotv.cn"))
}
