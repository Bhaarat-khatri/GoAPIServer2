package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/julienschmidt/httprouter"
)

var (
	verifier = emailverifier.NewVerifier().EnableSMTPCheck()
)

type Syntax struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Valid    bool   `json:"valid"`
}

// SMTP stores all information for SMTP verification lookup
type SMTP struct {
	HostExists  bool `json:"host_exists"` // is the host exists?
	FullInbox   bool `json:"full_inbox"`  // is the email account's inbox full?
	CatchAll    bool `json:"catch_all"`   // does the domain have a catch-all email address?
	Deliverable bool `json:"deliverable"` // can send an email to the email server?
	Disabled    bool `json:"disabled"`    // is the email blocked or disabled by the provider?
}

type Result struct {
	Email        string `json:"email"`          // passed email address
	Reachable    string `json:"reachable"`      // an enumeration to describe whether the recipient address is real
	Syntax       Syntax `json:"syntax"`         // details about the email address syntax
	SMTP         SMTP   `json:"smtp"`           // details about the SMTP response of the email
	Gravatar     string `json:"gravatar"`       // whether or not have gravatar for the email
	Suggestion   string `json:"suggestion"`     // domain suggestion when domain is misspelled
	Disposable   bool   `json:"disposable"`     // is this a DEA (disposable email address)
	RoleAccount  bool   `json:"role_account"`   // is account a role-based account
	Free         bool   `json:"free"`           // is domain a free email domain
	HasMxRecords bool   `json:"has_mx_records"` // whether or not MX-Records for the domain
}

func singleEmailVerify(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	email := r.URL.Query().Get("email")
	ret, err := verifier.Verify(email)
	index := strings.LastIndex(email, "@")
	username := email[:index]
	domain := strings.ToLower(email[index+1:])

	if err != nil {
		fmt.Println("verify email address failed, error is: ", err)
		e, err := json.Marshal(err)
		errs := Result{
			Email:     email,
			Reachable: "unknown",
			Syntax: Syntax{
				Username: username,
				Domain:   domain,
			},
			SMTP:       SMTP{},
			Gravatar:   "null",
			Suggestion: string(e),
		}

		b, err := json.Marshal(errs)

		if err != nil {
			fmt.Println("error:", err)
		}
		_, _ = fmt.Fprint(w, string(b))
		return
	}

	if !ret.Syntax.Valid {
		fmt.Println("email address syntax is invalid")
		return
	}
	
	bytes, err := json.Marshal(ret)
	fmt.Println(string(bytes))
	_, _ = fmt.Fprint(w, string(bytes))
}


func main() {

	//create router
	router := httprouter.New()
	//api route for verification
	router.GET("/singleverify/", singleEmailVerify)

	//start server
	log.Fatal(http.ListenAndServe(":8081", router))
}
