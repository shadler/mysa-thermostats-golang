package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
//	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp"
	"golang.org/x/net/http2"

	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"

	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	//"github.com/davecgh/go-spew/spew"
)


//	spew.Dump("49A")
//  flag.Parse()

func main() {
	username  := ""
	password  := ""
	client_id := "19efs8tgqe942atbqmot5m36t3"
	pool_id   := "us-east-1_GUFWfhI7g"

	fmt.Println("start", time.Now())

	var ctx = context.Background()

	mySession := session.Must(session.NewSession())

	svc := cognitoidentity.New(mySession, aws.NewConfig().WithRegion("us-east-1"))

	csrp, _ := cognitosrp.NewCognitoSRP(username, password, pool_id , client_id , nil)

	cfg, _ := external.LoadDefaultAWSConfig()

	cfg.Region = endpoints.UsEast1RegionID

	cfg.Credentials = aws2.AnonymousCredentials

	cognitoIdentityProvider2 := cip.New(cfg)


	initiateAuthRequest := cognitoIdentityProvider2.InitiateAuthRequest(&cip.InitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeUserSrpAuth,  	// "USER_SRP_AUTH"
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})

	initiateAuthRequest.Build()

	initiateAutheRespond, err := initiateAuthRequest.Send(ctx)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var IdToken string
	var RefreshToken string

	if initiateAutheRespond.ChallengeName == cip.ChallengeNameTypePasswordVerifier {
		challengeInput, _ := csrp.PasswordVerifierChallenge(initiateAutheRespond.ChallengeParameters, time.Now())
		chal := cognitoIdentityProvider2.RespondToAuthChallengeRequest(challengeInput)
		responseToAutheChallengeResponse, erro := chal.Send(ctx)
		if erro != nil {
			fmt.Println(err.Error())
			return
		}
		IdToken = *responseToAutheChallengeResponse.AuthenticationResult.IdToken
		RefreshToken = *responseToAutheChallengeResponse.AuthenticationResult.RefreshToken
	}

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	initiateAuthRequest = cognitoIdentityProvider2.InitiateAuthRequest(&cip.InitiateAuthInput{
		AuthFlow: cip.AuthFlowTypeRefreshTokenAuth,
		ClientId: aws.String(csrp.GetClientId()),
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": RefreshToken,
		},
	})

	initiateAuthRequest.Build()

	initiateAutheRespond, err = initiateAuthRequest.Send(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	
	IdToken = *initiateAutheRespond.AuthenticationResult.IdToken   // =====   IdToken

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	params := &cognitoidentity.GetIdInput{
		IdentityPoolId: aws.String("us-east-1:ebd95d52-9995-45da-b059-56b865a18379"), // Required
		Logins: map[string]*string{
			"cognito-idp.us-east-1.amazonaws.com/us-east-1_GUFWfhI7g": aws.String(IdToken), // Required
		},
	}

	getID, err := svc.GetId(params)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	credentialsForIdentityInput := &cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getID.IdentityId,
		Logins: map[string]*string{
			"cognito-idp.us-east-1.amazonaws.com/us-east-1_GUFWfhI7g": aws.String(IdToken),
		},
	}

	credentialsForIdentity, err := svc.GetCredentialsForIdentity(credentialsForIdentityInput)

	mySession.Config.WithCredentials(credentials.NewStaticCredentials(
		*credentialsForIdentity.Credentials.AccessKeyId,
		*credentialsForIdentity.Credentials.SecretKey,
		*credentialsForIdentity.Credentials.SessionToken))

	mySession.Config.WithRegion("us-east-1")

	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       true,
			MinVersion:               tls.VersionTLS11,
			MaxVersion:               tls.VersionTLS11,
		},
	}

	client2 := &http.Client{Transport: tr2}

	req10, err := http.NewRequest("GET", "https://app-prod.mysa.cloud/users/readingsForUser", nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	req10.Header.Set("accept", "application/json")
	req10.Header.Set("authorization", IdToken)
	req10.Header.Set("accept-encoding", "gzip")
	req10.Header.Set("user-agent", "okhttp/3.12.1")
	r := url.Values{}
	r.Add("ver", "2.8.2")
	r.Add("dev", "Nexus 5X")
	r.Add("os", "8.1.0")

	req10.URL.RawQuery = r.Encode()
	resp10, err2 := client2.Do(req10)

	if err2 != nil {
		fmt.Println(err2.Error())
		return
	}

	var jsonResult map[string]interface{}

	json.NewDecoder(resp10.Body).Decode(&jsonResult)
	j := jsonResult["devices"].(map[string]interface{})

	for key, _ := range j {
		fmt.Println("rec  ", key)
		show_j(key, j)
	}

	fmt.Println("end ", time.Now())
}

func show_j(k string, j map[string]interface{}) {
	j1 := j[k].(map[string]interface{})
	j2 := j1["Reading"].(map[string]interface{})
	for k, v := range j2 {
		var vv string
		switch v.(type) {
		case float64, float32:
			vv = fmt.Sprintf("%f", v)
		default:
			vv = fmt.Sprintf("%v", v)
		}

		fmt.Println("---  ", k, "  :", vv)
	}
}

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}


