default: client

server:
	@echo "> launch server ..."
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/server ./server/. && ./bin/server

print-%:
	@echo '$($*)'

.PHONY: client server