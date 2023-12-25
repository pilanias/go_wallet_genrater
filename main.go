package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jroimartin/gocui"
	"github.com/pilanias/go_wallet_genrater/bip39"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"gorm.io/gorm"
)

const (
	TotalWallets        = 4000
	ConcurrencyLevel    = 500 // Adjust this based on your machine's capabilities
	DefaultMnemonicBits = 128
)

// Generator is a function that generates a wallet.
type Generator func() (*Wallet, error)

// DefaultGenerator is the default wallet generator.
var DefaultGenerator = NewGeneratorMnemonic(DefaultMnemonicBits)

var (
	wg        sync.WaitGroup
	mu        sync.Mutex
	startTime time.Time
)

// Wallet represents a generated wallet.
type Wallet struct {
	Address    string
	PrivateKey string
	Mnemonic   string
	HDPath     string
	gorm.Model
	Bits int
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

func startGeneration(g *gocui.Gui) {
	// Start timer
	startTime = time.Now()
	// Initialize progress bar
	bar := progressbar.Default(int64(TotalWallets))

	for i := 0; i < ConcurrencyLevel; i++ {
		wg.Add(1)
		go generateWallets(bar, g)
	}

	wg.Wait()
	totalTime := time.Since(startTime).Seconds()
	walletsPerSecond := float64(TotalWallets) / totalTime
	fmt.Printf("\nTotal time taken: %.2f seconds\n", totalTime)
	fmt.Printf("Wallets per second: %.2f\n", walletsPerSecond)
}

func main() {
	// Initialize gocui
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		fmt.Println("Error initializing gocui:", err)
		return
	}
	defer g.Close()

	// Set gocui options and keybindings
	g.SetManagerFunc(layout)
	if err := keybindings(g); err != nil {
		fmt.Println("Error setting keybindings:", err)
		return
	}

	// Update addresses when the program starts

	// Start generation
	go startGeneration(g)

	// Run gocui main loop
	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		fmt.Println("Error running gocui main loop:", err)
		return
	}

	// Clear addresses on exit or program interruption

}

// layout is the gocui layout function.
func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("progress", 0, 0, maxX, maxY-2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Progress"
		v.Autoscroll = true
		v.Wrap = true
	}

	if v, err := g.SetView("log", 0, maxY-2, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Log"
		v.Autoscroll = true
		v.Wrap = true
	}

	return nil
}

// keybindings sets the gocui keybindings.
func keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		return err
	}

	return nil
}

// quit is the function to quit the program.
func quit(g *gocui.Gui, v *gocui.View) error {
	// Clear addresses on exit or program interruption

	return gocui.ErrQuit
}

// generateWallets generates the wallets and checks for target addresses.
func generateWallets(bar *progressbar.ProgressBar, g *gocui.Gui) {
	defer wg.Done()
	for i := 0; i < TotalWallets/ConcurrencyLevel; i++ {
		wallet, err := NewWallet()
		if err != nil {
			g.Update(func(g *gocui.Gui) error {
				v, _ := g.View("log")
				fmt.Fprintln(v, "Error generating wallet:", err)
				return nil
			})
			continue
		}

		mu.Lock()
		g.Update(func(g *gocui.Gui) error {
			v, _ := g.View("log")
			fmt.Fprintln(v, "Mnemonic:", wallet.Mnemonic)
			fmt.Fprintln(v, "Address:", wallet.Address)
			return nil
		})
		mu.Unlock()

		// Check if the generated wallet's address starts with any target address prefix

		for _, target := range bip39.TargetAddresses {
			if strings.HasPrefix(wallet.Address, target) {
				g.Update(func(g *gocui.Gui) error {
					v, _ := g.View("log")
					fmt.Fprintln(v, "\nTarget address found!")
					fmt.Fprintln(v, "Address:", wallet.Address)
					fmt.Fprintln(v, "Mnemonic:", wallet.Mnemonic)
					return nil
				})
				// Exit the program
				// Wait for 2 seconds before exiting
				time.Sleep(2 * time.Second)
				os.Exit(0)
			}
		}

		// Increment the progress bar
		bar.Add(1)
	}
}

// compelt code
