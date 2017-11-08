package routers

import (
	"github.com/gin-gonic/gin"
)

func ping(c *gin.Context) {
	c.String(200, "pong")
}
func init() {
	RouterMap.GET("/ping", ping)
}
