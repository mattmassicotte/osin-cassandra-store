package cassandrastore

import (
	"fmt"
	"time"
	"errors"
)

import (
	"github.com/gocql/gocql"
	"github.com/RangelReale/osin"
)

type CassandraStorage struct {
	cluster *gocql.ClusterConfig
}

func NewCassandraStorage(hosts []string, keyspace string) *CassandraStorage {
	r := &CassandraStorage{}

	r.cluster = gocql.NewCluster(hosts...)
	r.cluster.Keyspace = keyspace
	r.cluster.Consistency = gocql.Quorum

	return r
}

func (s *CassandraStorage) Clone() osin.Storage {
	return s
}

func (s *CassandraStorage) Close() {
}

func (s *CassandraStorage) GetClient(id string) (osin.Client, error) {
	fmt.Printf("GetClient: %s\n", id)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}
	defer session.Close()

	var secret string
	var redirectUri string

	query := session.Query(`SELECT secret, redirect_uri FROM clients WHERE id = ? LIMIT 1`, id)
	if err := query.Consistency(gocql.One).Scan(&secret, &redirectUri); err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	client := &osin.DefaultClient{Id: id, Secret: secret, RedirectUri: redirectUri}

	return client, nil
}

func (s *CassandraStorage) SetClient(id string, client osin.Client) error {
	fmt.Printf("SetClient: %s\n", id)
	// TODO
//	s.clients[id] = client
	return errors.New("Not implemented")
}

func (s *CassandraStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}
	defer session.Close()

	cql := "INSERT INTO access_grants (code, client_id, client_secret, scope, redirect_uri, state) VALUES (?, ?, ?, ?, ?, ?) USING TTL ?"
	query := session.Query(cql, data.Code, data.Client.GetId(), data.Client.GetSecret(), data.Scope, data.RedirectUri, data.State, data.ExpiresIn)
	if err := query.Exec(); err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	return nil
}

func (s *CassandraStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}
	defer session.Close()

	var clientId gocql.UUID
	var clientSecret string
	var aScope string
	var redirectUri string
	var state string
	var ttl int64

	query := session.Query(`SELECT client_id, client_secret, scope, redirect_uri, state, ttl(client_id) FROM access_grants WHERE code = ? LIMIT 1`, code)
	if err := query.Consistency(gocql.One).Scan(&clientId, &clientSecret, &aScope, &redirectUri, &state, &ttl); err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	// TODO: created at time
	client := &osin.DefaultClient{Id: clientId.String(), Secret: clientSecret, RedirectUri: redirectUri}
	data := &osin.AuthorizeData{Client: client, Code: code, ExpiresIn: int32(ttl), Scope: aScope, State: state, RedirectUri: redirectUri, CreatedAt: time.Now()}

	return data, nil
}

func (s *CassandraStorage) RemoveAuthorize(code string) error {
	if (code == "") {
		// This appears to be a osin bug, where certain grant types call
		// this function with a blank code
		return nil;
	}

	fmt.Printf("RemoveAuthorize: %s\n", code)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}
	defer session.Close()

	query := session.Query("DELETE FROM access_grants WHERE code = ?", code);
	if err := query.Exec(); err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	return nil
}

func (s *CassandraStorage) SaveAccess(data *osin.AccessData) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)

	err := s.internalSaveAccess(data, false)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	if (data.RefreshToken == "") {
		return nil
	}

	refreshData := *data
	refreshData.AccessToken = data.RefreshToken
	refreshData.RefreshToken = ""
	refreshData.ExpiresIn = 60 * 60 * 24 * 30 // 30 days
	err = s.internalSaveAccess(&refreshData, true)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	return nil
}

func (s *CassandraStorage) internalSaveAccess(data *osin.AccessData, isRefresh bool) error {
	fmt.Printf("internal SaveAccess: %s\n", data.AccessToken)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}
	defer session.Close()

	ttl := data.ExpiresIn * 4
	expiry := time.Now().Unix() + int64(data.ExpiresIn)

	if (data.AuthorizeData == nil) {
		data.AuthorizeData = &osin.AuthorizeData{Code: "", RedirectUri: "", State: ""}
	}

	cql := "INSERT INTO access_tokens "
	cql += "(code, client_id, client_secret, access_code, access_redirect_uri, access_state, is_refresh, refresh_token, scope, redirect_uri, expired_at, user_data) "
	cql += "VALUES "
	cql += "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?"
	query := session.Query(cql,
		data.AccessToken,
		data.Client.GetId(),
		data.Client.GetSecret(),
		data.AuthorizeData.Code,
		data.AuthorizeData.RedirectUri,
		data.AuthorizeData.State,
		isRefresh,
		data.RefreshToken,
		data.Scope,
		data.RedirectUri,
		expiry,
		data.UserData,
		ttl)
	if err := query.Exec(); err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	return nil
}

func (s *CassandraStorage) LoadAccess(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}
	defer session.Close()

	var clientId gocql.UUID
	var clientSecret string
	var accessCode string
	var accessRedirectUri string
	var accessState string
	var refreshToken string
	var aScope string
	var redirectUri string
	var expiresIn int64
	var userData string

	query := session.Query(`SELECT client_id, client_secret, access_code, access_redirect_uri, access_state, refresh_token, scope, redirect_uri, expired_at, user_data FROM access_tokens WHERE code = ? LIMIT 1`, code)
	if err := query.Consistency(gocql.One).Scan(&clientId, &clientSecret, &accessCode, &accessRedirectUri, &accessState, &refreshToken, &aScope, &redirectUri, &expiresIn, &userData); err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	client := &osin.DefaultClient{Id: clientId.String(), Secret: clientSecret, RedirectUri: redirectUri}
	data := &osin.AccessData{Client: client, AccessToken: code, RefreshToken: refreshToken, ExpiresIn: int32(expiresIn), Scope: aScope, RedirectUri: redirectUri, CreatedAt: time.Now(), UserData: userData}

	return data, nil
}

func (s *CassandraStorage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)

	session, err := s.cluster.CreateSession()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}
	defer session.Close()

	query := session.Query("DELETE FROM access_tokens WHERE code = ?", code);
	if err := query.Exec(); err != nil {
		fmt.Printf("error: %s\n", err)
		return err
	}

	return nil
}

func (s *CassandraStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadRefresh: %s\n", code)

	return s.LoadAccess(code)
}

func (s *CassandraStorage) RemoveRefresh(code string) error {
	fmt.Printf("RemoveRefresh: %s\n", code)

	return s.RemoveAccess(code)
}
