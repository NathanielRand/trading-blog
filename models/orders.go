package models

import "github.com/jinzhu/gorm"

type Order struct {
	gorm.Model
	SenderID uint `gorm:"not_null;index"`
	RecipientID uint `gorm:"not_null;index"`
	ReturnAddressID string
	// Status values: drafted,pending,approved,paid,dropoff,in-transit,delivered
	Status string `gorm:"not_null"`
	// ReturnAddress[] (user might change address en-route thus returning a different value when callling id)
	DestinationAddressID string
 	// DestinationAddress[]
	CarrierAddress string
	CarrierName string
	Cost int
	Discount int	
	Reported bool
	SenderSatisfaction int
	SenderReason string
	RecipientSatisfaction int
	RecipientReason string
	// InternalNotes []string
}

type OrderService interface {
	OrderDB
}

type OrderDB interface {
	Create(order *Order) error
}

type orderGorm struct {
	db *gorm.DB
}

func (og *orderGorm) Create(order *Order) error {
// 	todo
	return nil
}