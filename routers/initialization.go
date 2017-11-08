package routers

import (
	"github.com/gin-gonic/gin"
	"io"
	"os"
)

var RouterMap *gin.Engine

func ping(c *gin.Context) {
	c.String(200, "pong")
}
func init() {
	// Disable Console Color, you don't need console color when writing the logs to file.
	gin.DisableConsoleColor()

	// Logging to a file.
	f, _ := os.Create("gin.log")
	gin.DefaultWriter = io.MultiWriter(f)

	// Use the following code if you need to write the logs to file and console at the same time.
	// gin.DefaultWriter = io.MultiWriter(f, os.Stdout)

	RouterMap = gin.Default()
}
