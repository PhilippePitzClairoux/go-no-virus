package internal

import (
	"net/smtp"
)

type EmailNotifier struct {
	FromEmailAddress string `yaml:"from_email_address"`
	ToEmailAddress   string `yaml:"to_email_address"`
	Password         string `yaml:"password"`
	AuthUrl          string `yaml:"auth_url"`
	AuthUrlPort      string `yaml:"auth_url_port"`
}

var emailAuth smtp.Auth

func InitEmailNotifier(notifier *EmailNotifier) {
	emailAuth = smtp.PlainAuth(
		"",
		notifier.FromEmailAddress,
		notifier.Password,
		notifier.AuthUrl,
	)
}

func (en *EmailNotifier) SendVirusDetectionReport(data string) error {
	email :=
		"To: " + en.ToEmailAddress + "\r\n" +
			"Subject: Virus Detection Report\r\n" +
			"\r\n" +
			"Findings : \n" + data + "\r\n"

	return en.sendEmail(email)
}

func (en *EmailNotifier) sendEmail(email string) error {
	err := smtp.SendMail(en.AuthUrl+":"+en.AuthUrlPort, emailAuth, en.FromEmailAddress, []string{en.ToEmailAddress}, []byte(email))
	if err != nil {
		return err
	}

	return nil
}
