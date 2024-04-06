package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	
	"sync"
	 // Import the text/template package
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilanias/go_wallet_genrater/bip39"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	
	"gorm.io/gorm"
)

const (
	TotalWallets        = 4000
	ConcurrencyLevel    = 500
	DefaultMnemonicBits = 128
)

var (
	wg        sync.WaitGroup
	mu        sync.Mutex
	startTime time.Time
)

// Wallet represents a generated wallet.
type Wallet struct {
	gorm.Model
	Address    string
	PrivateKey string
	Mnemonic   string
	HDPath     string
	Bits       int
}

// Generator is a function that generates a wallet.
type Generator func() (*Wallet, error)

// DefaultGenerator is the default wallet generator.
var DefaultGenerator = NewGeneratorMnemonic(DefaultMnemonicBits)

func main() {
	startGeneration()
}

func startGeneration() {
	startTime = time.Now()
	bar := progressbar.Default(int64(TotalWallets))

	for i := 0; i < ConcurrencyLevel; i++ {
		wg.Add(1)
		go generateWallets(bar)
	}

	wg.Wait()
	printSummary()
}

func printSummary() {
	totalTime := time.Since(startTime).Seconds()
	walletsPerSecond := float64(TotalWallets) / totalTime

	fmt.Printf("\nTotal time taken: %.2f seconds\n", totalTime)
	fmt.Printf("Wallets per second: %.2f\n", walletsPerSecond)

	// After generation is complete, show the wallet details in a webview
	
}



func generateWallets(bar *progressbar.ProgressBar) {
	defer wg.Done()

	for i := 0; i < TotalWallets/ConcurrencyLevel; i++ {
		wallet, err := NewWallet()
		if err != nil {
			fmt.Println("Error generating wallet:", err)
			continue
		}
		


		printWalletDetails(wallet)

		if checkTargetAddresses(wallet.Address) {
			fmt.Println("Saving wallet to database...")
			fmt.Println(wallet.Address)
			fmt.Println(wallet.Mnemonic)
			os.Exit(0)
		}
		bar.Add(1)
	}
}

func printWalletDetails(wallet *Wallet) {
	mu.Lock()
	defer mu.Unlock()

	fmt.Println("Mnemonic:", wallet.Mnemonic)
	fmt.Println("Address:", wallet.Address)
}

// NewWallet generates a new wallet using the default generator.
func NewWallet() (*Wallet, error) {
	return DefaultGenerator()
}

// NewFromPrivatekey creates a new wallet from a given private key.
func NewFromPrivatekey(privateKey *ecdsa.PrivateKey) (*Wallet, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Convert private key to string.
	privKeyBytes := crypto.FromECDSA(privateKey)
	privString := hex.EncodeToString(privKeyBytes)

	// Convert public key to string.
	publicKey := &privateKey.PublicKey
	publicKeyBytes := crypto.Keccak256(crypto.FromECDSAPub(publicKey)[1:])[12:]
	if len(publicKeyBytes) > common.AddressLength {
		publicKeyBytes = publicKeyBytes[len(publicKeyBytes)-common.AddressLength:]
	}
	pubString := "0x" + hex.EncodeToString(publicKeyBytes)

	return &Wallet{
		Address:    pubString,
		PrivateKey: privString,
	}, nil
}

// NewGeneratorMnemonic creates a new wallet generator with the given mnemonic bit size.
func NewGeneratorMnemonic(bitSize int) Generator {
	return func() (*Wallet, error) {
		mnemonic, err := NewMnemonic(bitSize)
		if err != nil {
			return nil, err
		}

		privateKey, err := deriveWallet(bip39.NewSeed(mnemonic, ""), accounts.DefaultBaseDerivationPath)
		if err != nil {
			return nil, err
		}

		wallet, err := NewFromPrivatekey(privateKey)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		wallet.Bits = bitSize
		wallet.Mnemonic = mnemonic
		wallet.HDPath = accounts.DefaultBaseDerivationPath.String()
		return wallet, nil
	}
}

// NewMnemonic generates a new mnemonic with the given bit size.
func NewMnemonic(bitSize int) (string, error) {
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return "", errors.WithStack(err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return mnemonic, nil
}

// deriveWallet derives a wallet from the given seed and derivation path.
func deriveWallet(seed []byte, path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	privateKey, err := key.ECPrivKey()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return privateKey.ToECDSA(), nil
}

// checkTargetAddress checks if the generated address matches any of the target addresses.
func checkTargetAddresses(address string) bool {
	for _, target := range bip39.TargetAddresses {
		if strings.HasPrefix(address, target) {
			fmt.Println("\nTarget address found!")
			return true
		}
	}
	return false
}
