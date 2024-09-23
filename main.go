package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v2"
)

// 配置结构体
type Config struct {
	MySQL struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Database string `yaml:"database"`
		Prefix   string `yaml:"table_prefix"`
	} `yaml:"mysql"`
}

var config Config
var db *sql.DB

// 初始化 MySQL 连接
func initDB() {
	// 从配置文件读取 MySQL 配置
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("读取配置文件错误: %v", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("解析配置文件错误: %v", err)
	}

	// 构建数据源名称 (DSN)
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.MySQL.Username,
		config.MySQL.Password,
		config.MySQL.Host,
		config.MySQL.Port,
		config.MySQL.Database)

	// 连接到 MySQL 数据库
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("连接到数据库错误: %v", err)
	}

	// 确保数据库连接正常
	if err := db.Ping(); err != nil {
		log.Fatalf("数据库连接验证失败: %v", err)
	}

	log.Println("成功连接到 MySQL 数据库！")
}

// 用户结构体
type User struct {
	ID       int     `json:"id"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	Balance  float64 `json:"balance"`
	Token    string  `json:"token"`
}

// 记录日志到数据库
func logOperation(ip string, operation string) {
	query := fmt.Sprintf("INSERT INTO %slog (ip, operation, timestamp) VALUES (?, ?, ?)", config.MySQL.Prefix)
	_, err := db.Exec(query, ip, operation, time.Now())
	if err != nil {
		log.Printf("记录操作日志错误: %v", err)
	}
}

// 登录功能
func login(c *gin.Context) {
	ip := c.ClientIP()
	operation := "login"

	username := c.Request.URL.Query().Get("username")
	password := c.Request.URL.Query().Get("password")

	var user User
	var token sql.NullString // 用于捕获 token 字段的值

	// 查询用户信息
	query := fmt.Sprintf("SELECT id, username, password, balance, token FROM %susers WHERE username=? AND password=?", config.MySQL.Prefix)
	err := db.QueryRow(query, username, password).Scan(&user.ID, &user.Username, &user.Password, &user.Balance, &token)
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
		return
	}

	// 检查 token 是否为 NULL
	if !token.Valid {
		// token 字段为 NULL，将 'A' 插入到 token 字段
		updateQuery := fmt.Sprintf("UPDATE %susers SET token=? WHERE id=?", config.MySQL.Prefix)
		_, err = db.Exec(updateQuery, genToken(), user.ID)
		if err != nil {
			log.Printf("Failed to update token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "failed to update token"})
			return
		}
	} else {
		// 如果 token 不为 NULL，就更新他
		updateQuery := fmt.Sprintf("UPDATE %susers SET token=? WHERE id=?", config.MySQL.Prefix)
		_, err = db.Exec(updateQuery, genToken(), user.ID)
		if err != nil {
			log.Printf("Failed to update token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "failed to update token"})
			return
		}
	}
	err = db.QueryRow(query, username, password).Scan(&user.ID, &user.Username, &user.Password, &user.Balance, &token)
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
		return
	}
	// 返回成功响应
	c.JSON(http.StatusOK, gin.H{
		"status": "successfully",
		"token":  token.String,
	})

}

func genToken() string {
	now := time.Now()
	fiveMinutesLater := now.Add(5 * time.Minute)
	unixTimestamp := fiveMinutesLater.Unix()
	timestampStr := fmt.Sprintf("%d", unixTimestamp)
	hash := md5.Sum([]byte(timestampStr))
	hashStr := hex.EncodeToString(hash[:])
	return hashStr
}

// 更改密码功能
func changePassword(c *gin.Context) {
	ip := c.ClientIP()
	operation := "change_password"

	// 获取用户参数
	var request struct {
		Username    string `json:"username"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 验证旧密码并更新为新密码
	query := fmt.Sprintf("UPDATE %susers SET password=? WHERE username=? AND password=?", config.MySQL.Prefix)
	result, err := db.Exec(query, request.NewPassword, request.Username, request.OldPassword)
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "更新密码错误"})
		return
	}

	// 检查是否有行被更新
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logOperation(ip, operation)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "旧密码不正确"})
		return
	}

	logOperation(ip, operation)
	c.JSON(http.StatusOK, gin.H{"status": "密码更新成功"})
}

// 销毁 token 功能
func destroyToken(c *gin.Context) {
	ip := c.ClientIP()
	operation := "destroy_token"

	token := c.PostForm("token")

	// 从数据库中删除 token
	query := fmt.Sprintf("DELETE FROM %susers WHERE token=?", config.MySQL.Prefix)
	_, err := db.Exec(query, token)
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "销毁 token 失败"})
		return
	}

	logOperation(ip, operation)
	c.JSON(http.StatusOK, gin.H{"status": "token 销毁成功"})
}

// 查询用户钱包信息
func walletInfo(c *gin.Context) {
	ip := c.ClientIP()
	operation := "wallet_info"

	username := c.Query("username")

	var balance float64
	query := fmt.Sprintf("SELECT balance FROM %susers WHERE username=?", config.MySQL.Prefix)
	err := db.QueryRow(query, username).Scan(&balance)
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusNotFound, gin.H{"status": "用户未找到"})
		return
	}

	logOperation(ip, operation)
	c.JSON(http.StatusOK, gin.H{"username": username, "balance": balance})
}

// 转账功能
func transfer(c *gin.Context) {
	ip := c.ClientIP()
	operation := "transfer"

	var request struct {
		FromUser string  `json:"from_user"`
		ToUser   string  `json:"to_user"`
		Amount   float64 `json:"amount"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 使用事务处理转账
	tx, err := db.Begin()
	if err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "转账失败"})
		return
	}

	// 扣除发起者账户余额
	query := fmt.Sprintf("UPDATE %susers SET balance = balance - ? WHERE username = ? AND balance >= ?", config.MySQL.Prefix)
	_, err = tx.Exec(query, request.Amount, request.FromUser, request.Amount)
	if err != nil {
		tx.Rollback()
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "余额不足或更新失败"})
		return
	}

	// 增加接收者账户余额
	query = fmt.Sprintf("UPDATE %susers SET balance = balance + ? WHERE username = ?", config.MySQL.Prefix)
	_, err = tx.Exec(query, request.Amount, request.ToUser)
	if err != nil {
		tx.Rollback()
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "接收者更新失败"})
		return
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		logOperation(ip, operation)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "转账提交失败"})
		return
	}

	logOperation(ip, operation)
	c.JSON(http.StatusOK, gin.H{"status": "转账成功"})
}

func main() {
	// 初始化数据库
	initDB()

	router := gin.Default()

	// 注册路由
	router.POST("/auth/login", login)
	router.POST("/auth/chpasswd", changePassword)
	router.POST("/auth/destroy_token", destroyToken)
	router.POST("/transfer", transfer)
	router.GET("/wallet_info", walletInfo)

	router.Run(":56102")
}
