package connector

import (
	"encoding/hex"
	"testing"
)

func decodeKey(key string) []byte {
	s, err := hex.DecodeString(key)
	if err != nil {
		panic("failed to decode signature")
	}

	return s
}

func Test_validMAC(t *testing.T) {
	type args struct {
		message    []byte
		messageMAC []byte
		key        []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "basic test",
			args: args{
				message:    []byte("Hello World"),
				messageMAC: decodeKey("73715c9ace15e1392ad5247c4e1b1537a1927b204cdd3db6d8e8f2a5a39950e8"),
				key:        []byte("rawr123"),
			},
			want: true,
		},
		{
			name: "larger test",
			args: args{
				message:    []byte("bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGImbmFtZT1zYW0mdXNlcm5hbWU9c2Ftc2FtJmVtYWlsPXRlc3QlNDB0ZXN0LmNvbSZleHRlcm5hbF9pZD1oZWxsbzEyMyZyZXF1aXJlX2FjdGl2YXRpb249dHJ1ZQ=="),
				messageMAC: decodeKey("3d7e5ac755a87ae3ccf90272644ed2207984db03cf020377c8b92ff51be3abc3"),
				key:        []byte("d836444a9e4084d5b224a60c208dce14"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validMAC(tt.args.message, tt.args.messageMAC, tt.args.key); got != tt.want {
				t.Errorf("validMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnector_buildRedirectURL(t *testing.T) {
	type fields struct {
		secret       string
		discourseURL string
		cookieKey    []byte
		cookieName   string
	}
	type args struct {
		payload   string
		signature string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "base tests",
			fields: fields{
				secret:       "",
				discourseURL: "https://example.com",
				cookieKey:    nil,
				cookieName:   "",
			},
			args: args{
				payload:   "payload",
				signature: "signature",
			},
			want:    "https://example.com/session/sso_login?sig=signature&sso=payload",
			wantErr: false,
		},
		{
			name: "with bad path",
			fields: fields{
				secret:       "",
				discourseURL: "https://example.com/something/incorrect",
				cookieKey:    nil,
				cookieName:   "",
			},
			args: args{
				payload:   "payload",
				signature: "signature",
			},
			want:    "https://example.com/session/sso_login?sig=signature&sso=payload",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{
				secret:       tt.fields.secret,
				discourseURL: tt.fields.discourseURL,
				cookieKey:    tt.fields.cookieKey,
				cookieName:   tt.fields.cookieName,
			}
			got, err := c.buildRedirectURL(tt.args.payload, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connector.buildRedirectURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Connector.buildRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
