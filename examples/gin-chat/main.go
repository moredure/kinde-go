package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/frameworks/gin_kinde"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

type SessionStorage struct {
	session sessions.Session
}

func (storage *SessionStorage) GetItem(key string) string {
	value := storage.session.Get(key)
	if value == nil {
		return ""
	}
	return value.(string)
}

func (storage *SessionStorage) SetItem(key, value string) {
	storage.session.Set(key, value)
	storage.session.Save()
}

func main() {
	ConfigRuntime()
	StartWorkers()
	StartGin()
}

// ConfigRuntime sets the number of operating system threads.
func ConfigRuntime() {
	nuCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nuCPU)
	fmt.Printf("Running with %d CPUs\n", nuCPU)
}

// StartWorkers start starsWorker by goroutine.
func StartWorkers() {
	go statsWorker()
}

// StartGin starts gin web server with setting router.
func StartGin() {
	gin.SetMode(gin.DebugMode)

	router := gin.Default()

	store := memstore.NewStore([]byte("my session secret"))
	router.Use(sessions.Sessions("kinde-session", store))

	router.Use(rateLimit, gin.Recovery())
	router.LoadHTMLGlob("resources/*.templ.html")
	router.Static("/static", "resources/static")

	router.GET("/", index)

	privateGroup := router.Group("/")

	gin_kinde.UseKindeAuth(privateGroup,
		os.Getenv("KINDE_ISSUER_URL"),
		os.Getenv("KINDE_CLIENT_ID"),
		os.Getenv("KINDE_CLIENT_SECRET"),
		os.Getenv("KINDE_SITE_URL"),
		authorization_code.WithPrompt("login"),
	)

	privateGroup.GET("/room/:roomid", roomGET)
	privateGroup.POST("/room-post/:roomid", roomPOST)
	privateGroup.GET("/stream/:roomid", streamRoom)

	router.Run(":3000")
}
