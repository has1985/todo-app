package main

import (
	"log"
	"my/todo-app"
	"my/todo-app/pkg/handler"
)

func main() {

	handlers := new(handler.Handler)

	srv := new(todo.Server)
	if err := srv.Run("8000", handlers.InitRouters()); err != nil {
		log.Fatalf("error occured while running http server: %s", err.Error())
	}
}
