# Users microservicio

En esta carpeta se encuentra el código de aplicación users, la cual provee los métodos para la creación de usuarios y autenticación de los mismos.

Este proyecto hace uso de del mod de go para la gestión de dependencias.

# Estructura
````
├── config
|   └── config.go # Configuración del de la base de datos postgres
├── controller 
|   └── controller.go # Contiene la lógica de los casos de uso
|   └── controller_test.go # Contiene los test unitarios de la aplicación
├── model 
|   └── model.go # Contiene los modelos tanto de la base de datos, como de los dtos
└── docker-compose.yml # Archivo que permite el despligue único de la aplicación y su base de datos
└── Dockerfile # Archivo que permite la contenerización de la aplicación de go, contruye y despliega.
└── main.go # Archivo de inicio de la aplicación, instancia la base de datos y establece las rutas
└── README.md # Estás aquí
````

## Desplegar la aplicación en la máquina local

1. Install golang
2. Descargar las dependencias
```
cd users
go mod download
go mod tidy
```
3. Construir la aplicación
```
go build .\main.go
```
4. Ejecutar el archivo main.exe
```
.\main.exe
```

## Desplegar la aplicación con docker-compose

1. Construir la aplicación
```
docker-compose build
```
2. Desplegar los contenedores
```
docker-compose up -d
```

## Como ejecutar localmente las pruebas

1. Install golang
2. Ejecutar pruebas
```
cd users
go mod download
go test ./controller -coverprofile coverage.out -covermode count
go tool cover -html coverage.out
```# users-go
