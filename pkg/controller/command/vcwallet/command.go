/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/command/vcwallet")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VCWallet)

	// CreateProfileErrorCode for errors during create wallet profile operations.
	CreateProfileErrorCode

	// UpdateProfileErrorCode for errors during update wallet profile operations.
	UpdateProfileErrorCode

	// OpenWalletErrorCode for errors during update wallet unlock operations.
	OpenWalletErrorCode

	// CloseWalletErrorCode for errors during update wallet lock operations.
	CloseWalletErrorCode
)

// All command operations.
const (
	CommandName = "vcwallet"

	// command methods.
	CreateProfileMethod = "CreateProfile"
	UpdateProfileMethod = "UpdateProfile"
	OpenMethod          = "Open"
	CloseMethod         = "Close"
)

// miscellaneous constants for the vc wallet command controller.
const (
	// log constants.
	logSuccess = "success"
)

// provider contains dependencies for the verifiable credential wallet command controller
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
}

// Command contains operations provided by verifiable credential wallet controller.
type Command struct {
	ctx provider
}

// New returns new verifiable credential wallet controller command instance.
func New(p provider) *Command {
	return &Command{ctx: p}
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateProfileMethod, o.CreateProfile),
		cmdutil.NewCommandHandler(CommandName, UpdateProfileMethod, o.UpdateProfile),
		cmdutil.NewCommandHandler(CommandName, OpenMethod, o.Open),
		cmdutil.NewCommandHandler(CommandName, CloseMethod, o.Close),
	}
}

// CreateProfile creates new wallet profile for given user.
func (o *Command) CreateProfile(rw io.Writer, req io.Reader) command.Error {
	request := &CreateOrUpdateProfileRequest{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	// create profile.
	err = wallet.CreateProfile(request.UserID, o.ctx, prepareProfileOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

		return command.NewExecuteError(CreateProfileErrorCode, err)
	}

	// create EDV keys if profile is using local kms.
	if request.LocalKMSPassphrase != "" && request.EDVConfiguration != nil {
		err = wallet.CreateDataVaultKeyPairs(request.UserID, o.ctx, wallet.WithUnlockByPassphrase(request.LocalKMSPassphrase))
		if err != nil {
			logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

			return command.NewExecuteError(CreateProfileErrorCode, err)
		}
	}

	return nil
}

// UpdateProfile updates an existing wallet profile for given user.
func (o *Command) UpdateProfile(rw io.Writer, req io.Reader) command.Error {
	request := &CreateOrUpdateProfileRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UpdateProfileMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	// update profile.
	err = wallet.UpdateProfile(request.UserID, o.ctx, prepareProfileOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UpdateProfileMethod, err.Error())

		return command.NewExecuteError(UpdateProfileErrorCode, err)
	}

	return nil
}

// Open unlocks given user's wallet and returns a token for subsequent use of wallet features.
func (o *Command) Open(rw io.Writer, req io.Reader) command.Error {
	request := &UnlockWalletRquest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewExecuteError(OpenWalletErrorCode, err)
	}

	token, err := vcWallet.Open(prepareUnlockOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewExecuteError(OpenWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, UnlockWalletResponse{Token: token}, logger)
	logutil.LogDebug(logger, CommandName, OpenMethod, logSuccess)

	return nil
}

// Close locks given user's wallet.
func (o *Command) Close(rw io.Writer, req io.Reader) command.Error {
	request := &LockWalletRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CloseMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CloseMethod, err.Error())

		return command.NewExecuteError(CloseWalletErrorCode, err)
	}

	closed := vcWallet.Close()

	command.WriteNillableResponse(rw, LockWalletResponse{Closed: closed}, logger)
	logutil.LogDebug(logger, CommandName, OpenMethod, logSuccess)

	return nil
}

// prepareProfileOptions prepares options for creating wallet profile.
func prepareProfileOptions(rqst *CreateOrUpdateProfileRequest) []wallet.ProfileOptions {
	var options []wallet.ProfileOptions

	if rqst.LocalKMSPassphrase != "" {
		options = append(options, wallet.WithPassphrase(rqst.LocalKMSPassphrase))
	}

	if rqst.KeyStoreURL != "" {
		options = append(options, wallet.WithKeyServerURL(rqst.KeyStoreURL))
	}

	if rqst.EDVConfiguration != nil {
		options = append(options, wallet.WithEDVStorage(
			rqst.EDVConfiguration.ServerURL, rqst.EDVConfiguration.VaultID,
			rqst.EDVConfiguration.EncryptionKeyID, rqst.EDVConfiguration.MACKeyID,
		))
	}

	return options
}

func prepareUnlockOptions(rqst *UnlockWalletRquest) []wallet.UnlockOptions {
	var options []wallet.UnlockOptions

	if rqst.LocalKMSPassphrase != "" {
		options = append(options, wallet.WithUnlockByPassphrase(rqst.LocalKMSPassphrase))
	}

	if rqst.WebKMSAuth != "" {
		options = append(options, wallet.WithUnlockByAuthorizationToken(rqst.LocalKMSPassphrase))
	}

	// TODO edv sign header function for zcap support #2433
	if rqst.EDVUnlock != nil {
		if rqst.EDVUnlock.AuthToken != "" {
			options = append(options, wallet.WithUnlockEDVOptions(edv.WithHeaders(
				func(req *http.Request) (*http.Header, error) {
					req.Header.Set("authorization", fmt.Sprintf("Bearer %s", rqst.EDVUnlock.AuthToken))

					return &req.Header, nil
				},
			)))
		}
	}

	// TODO web kms sign header function for zcap support #2433
	return options
}
