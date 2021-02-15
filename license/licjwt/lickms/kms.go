package lickms

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/mariotoffia/gojwtlic/license"
)

// TODO: Use KMS to sign key: https://www.altostra.com/blog/asymmetric-jwt-signing-using-aws-kms

// KMSManager handles _AWS KMS_ communication.
//
// NOTE: Depending on the current process credentials, it may or may not succeed in the operations!
type KMSManager struct {
	cfg     aws.Config
	ctx     context.Context
	err     error
	replus  *regexp.Regexp
	reslash *regexp.Regexp
	reeq    *regexp.Regexp
	client  *kms.Client
}

// NewKMSManager creates a new KMS manager to communicate with _AWS KMS_.
func NewKMSManager(ctx context.Context) *KMSManager {

	cfg, err := config.LoadDefaultConfig(ctx)

	return &KMSManager{
		err:     err,
		cfg:     cfg,
		client:  kms.NewFromConfig(cfg),
		replus:  regexp.MustCompile(`/\+/g`),
		reslash: regexp.MustCompile(`/\//g`),
		reeq:    regexp.MustCompile("/=/g"),
	}

}

// Error returns the error state of `KMSManager`
func (km *KMSManager) Error() error {
	return km.err
}

// ClearError will clear any error state
func (km *KMSManager) ClearError() *KMSManager {
	km.err = nil
	return km
}

// CreateKey will create a key in the _KMS_. If successfull it return the _ARN_ of the newly created key.
//
// The tags is optional, just provide `nil` if not tags is wanted.
// If you do not provide a key policy, _AWS KMS_ attaches a default key policy to the CMK. For more
// information, see Default Key Policy (https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html#key-policy-default)
// in the AWS Key Management Service Developer Guide. The key policy size quota is 32 kilobytes (32768 bytes).
func (km *KMSManager) CreateKey(kt license.KeyType, bits int, tags *map[string]string, policy string) string {

	if km.err != nil {
		return ""
	}

	var cmksp string
	switch kt {
	case license.RSAKeyType:
		cmksp = fmt.Sprintf("RSA_%d", bits)
	case license.ECCNist:
		cmksp = fmt.Sprintf("ECC_NIST_P%d", bits)
	case license.ECCSEGCG:
		cmksp = fmt.Sprintf("ECC_SECG_P%dK1", bits)
	}

	description := "Used for licensing purposes"

	input := &kms.CreateKeyInput{
		CustomerMasterKeySpec: types.CustomerMasterKeySpec(cmksp),
		Origin:                types.OriginTypeAwsKms,
		KeyUsage:              types.KeyUsageTypeSignVerify,
		Description:           &description,
		Tags:                  mapToTags(tags),
	}

	if policy != "" {
		input.Policy = &policy
	}

	result, err := km.client.CreateKey(km.ctx, input)

	if err != nil {
		km.err = err
	}

	return *result.KeyMetadata.Arn
}

// Sign will sign the _msg_ using the _keyID ARN_. It signs the _msg_ using the algorithm specified by
// _kt_ with _SHA_ with bitlength of _shabits_. If _RSA_ and _PKCS1_V1_5_ is wanted set _pkcs_ to `true`.
//
// The returned data is a signature is a _JWT_ compatible signature that may be . concatenated with the _msg_
// payload.
//
// .Example Usage
// [source,go]
// ....
// header := []byte(`{ "alg": "RS256", "typ":"JWT" }`)
// body := []byte(`{ "scope":"admin" }`)
// msg := append(header, []byte("."), body) // <1>
//
// sig := x.Sign("arn", license.RSAKeyType, 256, true, msg) // <2>
//
// jwt := append(msg, []byte("."), sig) // <3>
// ....
// <1> Payload to sign using the KMS
// <2> The actual call to _AWS KMS_ to sign the _msg_
// <3> This is now a valid _JWT_ that may be validated using the _public key_ gotten from _KMS_
func (km *KMSManager) Sign(keyID string, kt license.KeyType, shabits int, pkcs bool, msg []byte) []byte {

	if km.err != nil {
		return nil
	}

	input := &kms.SignInput{
		KeyId:            &keyID,
		Message:          msg,
		SigningAlgorithm: sigAlgFromKeyTypeAndBits(kt, shabits, pkcs),
		MessageType:      types.MessageTypeRaw,
	}

	result, err := km.client.Sign(km.ctx, input)

	if err != nil {
		km.err = err
	}

	token, err := base64.StdEncoding.DecodeString(string(result.Signature))

	if err != nil {
		km.err = err
		return nil
	}

	token = km.replus.ReplaceAll(token, []byte("-"))
	token = km.reslash.ReplaceAll(token, []byte("_"))
	token = km.reeq.ReplaceAll(token, []byte(""))

	return token
}

// Verify will take the same parameters except that it in addition takes a signature to verify using _KMS_.
//
// Use this method if no public certificate is downloaded and the verification is done in the _KMS_ instead
// of locally at backend or lambda etc.
func (km *KMSManager) Verify(keyID string, kt license.KeyType, shabits int, pkcs bool, msg, sig []byte) bool {

	if km.err != nil {
		return false
	}

	input := &kms.VerifyInput{
		KeyId:            &keyID,
		Message:          msg,
		Signature:        sig,
		SigningAlgorithm: sigAlgFromKeyTypeAndBits(kt, shabits, pkcs),
		MessageType:      types.MessageTypeRaw,
	}

	result, err := km.client.Verify(km.ctx, input)

	if err != nil {
		km.err = err
		return false
	}

	return result.SignatureValid
}

// GetPublicKey gets the associated public key from a key in _KMS_ addressed by
// it _ARN_ or alias.
func (km *KMSManager) GetPublicKey(keyID string) []byte {

	if km.err != nil {
		return nil
	}

	input := &kms.GetPublicKeyInput{
		KeyId: &keyID,
	}

	result, err := km.client.GetPublicKey(km.ctx, input)

	if err != nil {
		km.err = err
		return nil
	}

	return result.PublicKey
}

// ScheduleDeleteKey schedules a deletion of a key _ARN_ or alias. The _pendingDays_ must be
// between 7 and 30.
func (km *KMSManager) ScheduleDeleteKey(keyID string, pendingDays int32) *KMSManager {

	if km.err != nil {
		return km
	}

	if pendingDays < 7 {
		pendingDays = 7
	}

	if pendingDays > 30 {
		pendingDays = 30
	}

	input := &kms.ScheduleKeyDeletionInput{
		KeyId:               &keyID,
		PendingWindowInDays: &pendingDays,
	}

	if _, err := km.client.ScheduleKeyDeletion(km.ctx, input); err != nil {
		km.err = err
	}

	return km
}

func sigAlgFromKeyTypeAndBits(kt license.KeyType, shabits int, pkcs bool) types.SigningAlgorithmSpec {

	if kt == license.RSAKeyType && pkcs {
		return types.SigningAlgorithmSpec(fmt.Sprintf("RSASSA_PKCS1_V1_5_SHA_%d", shabits))
	}

	if kt == license.RSAKeyType && !pkcs {
		return types.SigningAlgorithmSpec(fmt.Sprintf("RSASSA_PSS_SHA_%d", shabits))
	}

	return types.SigningAlgorithmSpec(fmt.Sprintf("ECDSA_SHA_%d", shabits))
}

// mapToTags converts a map of string, string to _AWS_ tags
func mapToTags(tags *map[string]string) []types.Tag {
	t := []types.Tag{}

	if nil == tags || len(*tags) == 0 {
		return t
	}

	for k, v := range *tags {

		t = append(t, types.Tag{
			TagKey:   &k,
			TagValue: &v,
		})

	}

	return t
}
