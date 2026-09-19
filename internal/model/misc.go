//go:generate go tool go-enum --names --values --marshal --sql
package model

// ENUM(FDFZ = fdfz,FFXH = ffxh,FFQP = ffqp,FFPD = ffpd, FFJA = ffja)
type School string

// ENUM(library, computer_room)
type SchoolPlace string
