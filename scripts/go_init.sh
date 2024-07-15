#!/bin/bash
source ./scripts/variables.sh
go install golang.org/x/mobile/cmd/gomobile@latest

gomobile init
cd ./go
go mod download
