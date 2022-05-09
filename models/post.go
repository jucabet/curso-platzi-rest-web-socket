package models

import "time"

type Post struct {
	Id          string    `json:"id"`
	PostContent string    `json:"post_content"`
	CreateAt    time.Time `json:"create_at,omitempty"`
	UserId      string    `json:"user_id,omitempty"`
}
