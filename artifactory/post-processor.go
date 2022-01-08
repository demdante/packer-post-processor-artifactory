//go:generate mapstructure-to-hcl2 -type Config

package artifactory

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2/hcldec"
	common "github.com/hashicorp/packer-plugin-sdk/common"
	"github.com/hashicorp/packer-plugin-sdk/packer"
	"github.com/hashicorp/packer-plugin-sdk/template/config"
	"github.com/hashicorp/packer-plugin-sdk/template/interpolate"
)

type Config struct {
	BoxName             string `mapstructure:"box_name"`
	BoxDir              string `mapstructure:"box_dir"`
	Version             string `mapstructure:"version"`
	Date                string `mapstructure:"date"`
	BlobURL             string `mapstructure:"url"`
	Repo                string `mapstructure:"repo"`
	AuthKey             string `mapstructure:"key"`
	common.PackerConfig `mapstructure:",squash"`

	ctx interpolate.Context
}

type PostProcessor struct {
	config Config
}

func (p *PostProcessor) ConfigSpec() hcldec.ObjectSpec { return p.config.FlatMapstructure().HCL2Spec() }

func (p *PostProcessor) Configure(raws ...interface{}) error {
	err := config.Decode(&p.config, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &p.config.ctx,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{"output"},
		},
	}, raws...)
	if err != nil {
		return err
	}

	errs := new(packer.MultiError)

	// required configuration
	templates := map[string]*string{
		"url": &p.config.BlobURL,
	}

	for key, ptr := range templates {
		if *ptr == "" {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("Artifactory plugin %s must be set", key))
		}
	}

	// Template process
	for key, ptr := range templates {
		if err = interpolate.Validate(*ptr, &p.config.ctx); err != nil {
			errs = packer.MultiErrorAppend(
				errs, fmt.Errorf("Error parsing %s template: %s", key, err))
		}
	}
	if len(errs.Errors) > 0 {
		return errs
	}

	return nil
}

func (p *PostProcessor) PostProcess(ctx context.Context, ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, bool, error) {
	box := artifact.Files()[0]
	if !strings.HasSuffix(box, ".ova") {
		return nil, false, false, fmt.Errorf("Unknown files in artifact from vagrant post-processor: %s", artifact.Files())
	}

	// determine box size
	boxStat, err := os.Stat(box)
	if err != nil {
		return nil, false, false, err
	}

	// determine version
	version := p.config.Version
	date := p.config.Date
	ui.Message(fmt.Sprintf("Box to upload: %s (%d bytes) Version: %s  Date: %s", box, boxStat.Size(), version, date))

	ui.Message("Generating checksums")

	f, err := os.OpenFile(box, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalln("Cannot open file: %s", box)
	}
	defer f.Close()
	info := CalculateBasicHashes(f)

	ui.Message(fmt.Sprintf("md5    :", info.Md5))
	ui.Message(fmt.Sprintf("sha1   :", info.Sha1))
	ui.Message(fmt.Sprintf("sha256 :", info.Sha256))
	ui.Message(fmt.Sprintf("sha512 :", info.Sha512))

	//upload the box to artifactory
	err = p.uploadBox(box, ui, info)

	if err != nil {
		return nil, false, false, err
	}
	return nil, true, true, nil
}

func (p *PostProcessor) uploadBox(box string, ui packer.Ui, hashInfo HashInfo) error {
	// open the file for reading
	file, err := os.Open(box)
	if err != nil {
		return err
	}

	defer file.Close()
	importRepo := p.config.BlobURL
	AuthKey := p.config.AuthKey
	repo := p.config.Repo
	if err != nil {
		return err
	}

	if importRepo == "" {
		importRepo = fmt.Sprintf("http://localhost:8080/'%s'/'%s'", repo, box)
	} else {
		importRepo = fmt.Sprintf("%s/%s/%s/%s.ova"+";version=%s;date=%s", importRepo, repo, p.config.BoxDir, p.config.BoxName, p.config.Version, p.config.Date)
	}

	ui.Message(importRepo)

	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	resp, err := http.NewRequest("PUT", importRepo, file)
	resp.Header.Set("X-JFrog-Art-Api", AuthKey)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{}
	res, err := client.Do(resp)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	scanner.Split(bufio.ScanBytes)
	var buffer bytes.Buffer
	for scanner.Scan() {
		buffer.WriteString(scanner.Text())
	}
	ui.Message(buffer.String())

	if res.StatusCode != 201 {
		return errors.New("Error uploading File")
	}
	return err
}

type HashInfo struct {
	Md5    string `json:"md5"`
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
	Sha512 string `json:"sha512"`
}

func CalculateBasicHashes(rd io.Reader) HashInfo {

	hMd5 := md5.New()
	hSha1 := sha1.New()
	hSha256 := sha256.New()
	hSha512 := sha512.New()

	// For optimum speed, Getpagesize returns the underlying system's memory page size.
	pagesize := os.Getpagesize()

	// wraps the Reader object into a new buffered reader to read the files in chunks
	// and buffering them for performance.
	reader := bufio.NewReaderSize(rd, pagesize)

	// creates a multiplexer Writer object that will duplicate all write
	// operations when copying data from source into all different hashing algorithms
	// at the same time
	multiWriter := io.MultiWriter(hMd5, hSha1, hSha256, hSha512)

	// Using a buffered reader, this will write to the writer multiplexer
	// so we only traverse through the file once, and can calculate all hashes
	// in a single byte buffered scan pass.
	//
	_, err := io.Copy(multiWriter, reader)
	if err != nil {
		panic(err.Error())
	}

	var info HashInfo

	info.Md5 = hex.EncodeToString(hMd5.Sum(nil))
	info.Sha1 = hex.EncodeToString(hSha1.Sum(nil))
	info.Sha256 = hex.EncodeToString(hSha256.Sum(nil))
	info.Sha512 = hex.EncodeToString(hSha512.Sum(nil))

	return info
}

// converts a packer builder name to the corresponding vagrant provider
func providerFromBuilderName(name string) string {
	switch name {
	case "vmware":
		return "vmware_desktop"
	default:
		return name
	}
}
