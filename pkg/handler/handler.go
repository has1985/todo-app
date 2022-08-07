package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/has1985/todo-app/pkg/service"
)

type Handler struct {
	services *service.Service
}

func NewHandler(services *service.Service) *Handler {
	return &Handler{services: services}
}

func (h *Handler) InitRouters() *gin.Engine {

	router := gin.New()
	auth := router.Group("/auth")
	{
		auth.POST("/sign-up", h.signUp)
		auth.POST("sign-in", h.signIn)
	}

	api := router.Group("/api")
	{
		lists := api.Group("/lists")
		{
			lists.POST("/", h.createList)
			lists.GET("/", h.getAllList)
			lists.GET("/:id", h.getListById)
			lists.PUT("/:id", h.updateList)
			lists.DELETE("/:id", h.deleteList)
		}
		items := lists.Group(":id/items")
		{
			items.POST("/", h.createItem)
			items.GET("/", h.getAllItem)
			items.GET("/:item_id", h.getItemById)
			items.PUT("/:item-id", h.updateItem)
			items.DELETE("/:item_id", h.deleteItem)
		}
	}
	return router
}
