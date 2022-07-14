package main

import (
	"fmt"
	"log"
	"strings"

	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"time"

	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Users struct {
	gorm.Model
	Name string `gorm:"type:varchar(20);not null"`

	Password string `gorm:"size:255;not null"`
}

var jwtkey = []byte("a_secret_crect")

type Claims struct {
	UserId uint
	jwt.StandardClaims
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 获取 authorization header
		tokenString := ctx.GetHeader("Authorization")

		fmt.Print("请求token", tokenString)

		//validate token formate
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"code": 401,
				"msg":  "权限不足",
			})
			ctx.Abort()
			return
		}

		tokenString = tokenString[7:] //截取字符

		token, claims, err := ParseToken(tokenString)

		if err != nil || !token.Valid {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"code": 401,
				"msg":  "权限不足",
			})
			ctx.Abort()
			return
		}

		//token通过验证, 获取claims中的UserID
		userId := claims.UserId
		db := InitDB()
		db.DB()
		var user Users
		db.First(&user, userId)

		// 验证用户是否存在
		if user.ID == 0 {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"code": 401,
				"msg":  "权限不足",
			})
			ctx.Abort()
			return
		}

		//用户存在 将user信息写入上下文
		ctx.Set("user", user)

		ctx.Next()
	}
}
func ReleaseToken(user Users) (string, error) {

	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{

		UserId: user.ID,
		StandardClaims: jwt.StandardClaims{

			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "wzANDwz",
			Subject:   "user token",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtkey, nil
	})

	return token, claims, err
}
func main() {

	db := InitDB()
	db.DB()
	r := gin.Default()
	r.POST("/api/reg", func(ctx *gin.Context) {

		// name := ctx.PostForm("name")

		Name := ctx.PostForm("name")
		password := ctx.PostForm("password")

		if len(password) != 11 {

			ctx.JSON(http.StatusUnprocessableEntity, gin.H{"code": 422, "msg": "密码必须为11位!"})
			return
		}

		if ispasswds(db, Name) {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{"code": 422, "msg": "存在"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
			return
		}
		newUser := Users{
			Password: string(hashedPassword),
			Name:     Name,
		}

		db.Create(&newUser)

		ctx.JSON(200, gin.H{

			"msg": "成功!",
		})

	})

	r.POST("/api/login", func(ctx *gin.Context) {

		Name := ctx.PostForm("name")
		password := ctx.PostForm("password")

		var user Users
		db.Where("name = ?", Name).First(&user)
		if user.ID == 0 {

			ctx.JSON(http.StatusUnprocessableEntity, gin.H{"code": 422, "msg": "不存在"})

			return
		}
		//
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {

			ctx.JSON(http.StatusUnprocessableEntity, gin.H{"code": 422, "msg": "错误"})
			return

		}

		token, err := ReleaseToken(user)
		if err != nil {

			ctx.JSON(http.StatusUnprocessableEntity, gin.H{"code": 422, "msg": "token错误"})
			log.Printf("token : %v", err)
			return
		}
		ctx.JSON(200, gin.H{

			"date": gin.H{"token": token},
			"msg":  "登录成功!",
		})

	})

	r.GET("api/info", AuthMiddleware(), func(ctx *gin.Context) {

		user, _ := ctx.Get("user")
		ctx.JSON(http.StatusOK, gin.H{"code": 200, "dare": gin.H{"user": user}})

	})

	r.Run(":9090")

}

func ispasswds(db *gorm.DB, name string) bool {
	var user Users
	db.Where("name = ?", name).First(&user)
	if user.ID != 0 {

		return true
	}
	return false
}

func InitDB() *gorm.DB {

	host := "127.0.0.1"
	port := "3306"
	database := "golang"
	username := "golang"
	password := "golang"

	args := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&loc=%s&parseTime=true", username, password, host, port, database, url.QueryEscape("Asia/Shanghai"))
	db, err := gorm.Open(mysql.Open(args))

	if err != nil {

		panic("err!")
	}
	db.AutoMigrate(Users{})

	return db
}
