package db

import (
	"fmt"

	"go-collector/internal/config"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// OpenMySQLDB создаёт sqlx-подключение из company/app конфигов.
func OpenMySQLDB(company *config.CompanyConfig, app *config.AppConfig) (*sqlx.DB, error) {
	url, err := company.DBURL(app)
	if err != nil {
		return nil, err
	}
	db, err := sqlx.Open("mysql", url)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// PingMySQLDB проверяет доступность БД на инфраструктурном уровне.
// Вызывается в composition root до создания репозитория.
func PingMySQLDB(db *sqlx.DB) error {
	if db == nil {
		return fmt.Errorf("nil db")
	}
	return db.Ping()
}
