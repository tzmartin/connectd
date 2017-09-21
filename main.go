package main

import (
	"archive/tar"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Jeffail/gabs"
	log "github.com/Sirupsen/logrus"
	"github.com/tzmartin/namedpiper"
)

var (
	pub               = flag.String("pub", "dariconnect", "Publish to unix named pipe (fifo)")
	sub               = flag.String("sub", "dariconnect", "Subscribe to unix named pipe (fifo). Defaults to dariconnect")
	message           = flag.String("message", "", "JSON encoded string")
	FIFO_DIR          = flag.String("dir", "/tmp/pipes", "FIFO directory absolute path")
	completeDirectory = flag.String("complete_dir", "", "directory to stash completed files")
	stagingDirectory  = flag.String("staging_dir", "", "directory to stash tar files upon creation")
)

//create a map for storing clear funcs
var clear map[string]func()

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}

	return (err != nil)
}

func deleteFile(p string) {
	var err = os.Remove(p)
	if isError(err) {
		return
	}

	fmt.Println("Deleted file")
}

func cleanup() {
	//deleteFile(fmt.Sprintf("%s/%s", *FIFO_DIR, *sub))
}

func init() {
	log.SetFormatter(&log.TextFormatter{})
}

// This is where we can maintain the white list of files to grab out of a session
func fileWhiteListHandler(path string) string {
	fmt.Println("Inspecting:  ", path)
	return path
}

func tarit(source, target string) error {
	filename := filepath.Base(source)
	fmt.Println("filename var is: ", filename)
	target = filepath.Join(target, fmt.Sprintf("%s.tar", filename))
	fmt.Println("targer var is: ", target)
	tarfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer tarfile.Close()

	tarball := tar.NewWriter(tarfile)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if err := tarball.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tarball, file)
		return err
	})
}

func hash_file_md5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

// UploadGCS Upload a file to Google Cloud Storage
func UploadGCS(filepath, filename string) (err error) {

	fileToUpload, err := os.Open(filepath + "/" + filename)
	if err != nil {
		fmt.Println(err)
	}

	hash, err := hash_file_md5(filepath + "/" + filename)
	if err == nil {
		fmt.Println(hash)
	}
	md5Checksum := hash

	defer fileToUpload.Close()
	req, err := http.NewRequest("POST", "https://www.googleapis.com/upload/storage/v1/b/sai-corp-dev-session-ingest/o?uploadType=media&name="+filename, fileToUpload)
	if err != nil {
		// handle err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle err
	}

	if resp.StatusCode == 200 {
		println("Initial checksum was: ", md5Checksum)
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println("post:\n", string(body))
		if err != nil {
		}

		// TODO: clean up  this seems rediculous
		responseParsed, _ := gabs.ParseJSON([]byte(string(body)))
		gcsMd5Base64 := responseParsed.Path("md5Hash").Data()
		var gcsMd5Base64String = gcsMd5Base64.(string)
		gcsMd5Hex, err := base64.StdEncoding.DecodeString(gcsMd5Base64String)
		if err != nil {
			log.Fatal("error:", err)
		}
		fmt.Println("gcs hash is", gcsMd5Hex)
	}

	defer resp.Body.Close()
	return
}

func main() {
	print("\033[H\033[2J")
	flag.Parse()
	fmt.Println("\nDARI Connect")
	fmt.Println("Version 0.0.2")
	fmt.Println("Copyright (c) 2017 Scientific Analytics, Inc.")
	fmt.Println("")
	fmt.Println("---FLAGS---")
	flag.Visit(func(a *flag.Flag) {
		fmt.Println(a.Name, "=", a.Value)
	})
	fmt.Println("-----------")

	// fmt.Printf("OS: %s\nArchitecture: %s\n", runtime.GOOS, runtime.GOARCH)

	// listen for OS signals and force cleanup
	// https://stackoverflow.com/questions/41432193/how-to-delete-a-file-using-golang-on-program-exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cleanup()
		os.Exit(0)
	}()

	if *sub != "" && *message == "" {
		channel, err := namedpiper.Register(*sub, *FIFO_DIR)
		defer namedpiper.Unregister(*sub)

		if err != nil {
			log.Panic(fmt.Sprintf("Could not create fifo: %s exists", *sub))
		}

		fmt.Printf("Subscribed to channel: %s\n", *sub)
		fmt.Printf("Dir: %s\n", *FIFO_DIR)
		fmt.Printf("\nWaiting for events (refer to -help)\n\n")
		for {
			msg := <-channel
			log.Info(msg.String())
			jsonParsed, _ := gabs.ParseJSON([]byte(msg.String()))

			status := jsonParsed.Path("status").Data()

			switch statusState := status; statusState {
			case "REQUEST-NEW-SESSION":

				body := strings.NewReader(msg.String())
				req, err := http.NewRequest("POST", "https://sp-gcp-alpha.appspot.com/session", body)
				if err != nil {
					// handle err
				}
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					// handle err
				}
				fmt.Println(resp.Body)
				defer resp.Body.Close()
				// {
				// "uid": "ABCD1234",
				// "fname": "bob",
				// "lname": "jones",
				// "height": "70",
				// "weight": "180",
				// "protocol": [],
				// "prompt": true
				// }

			case "SESSION-COMPLETE":
				captureDirectory := jsonParsed.Path("data.path").Data().(string)
				fmt.Println("stagingDirectory is: ", *stagingDirectory)
				err := tarit(captureDirectory, *stagingDirectory)
				if err != nil {
					log.Info("was unable to tar file, captureDirectory:", captureDirectory, " stagingDirectory  ", *stagingDirectory)

				}
				filename := filepath.Base(*stagingDirectory)

				// fmt.Println(reflect.TypeOf(uploadFile))
				filename = filepath.Base(captureDirectory)
				target := filepath.Join(*stagingDirectory, fmt.Sprintf("%s.tar", filename))

				log.Info("Uploading to GCS: ", target)
				UploadGCS(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
				fullCompleteFile := []string{*completeDirectory, "/", filename, ".tar"}

				err = os.Rename(target, strings.Join(fullCompleteFile, ""))

				if err != nil {
					fmt.Println(err)
					return
				}

			case "SESSION-PARTIAL":
				captureDirectory := jsonParsed.Path("data.path").Data().(string)
				fmt.Println("stagingDirectory is: ", *stagingDirectory)
				err := tarit(captureDirectory, *stagingDirectory)
				if err != nil {
					log.Info("was unable to tar file, captureDirectory:", captureDirectory, " stagingDirectory  ", *stagingDirectory)

				}
				filename := filepath.Base(*stagingDirectory)

				// fmt.Println(reflect.TypeOf(uploadFile))
				filename = filepath.Base(captureDirectory)
				target := filepath.Join(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
				fullStagingFile := []string{captureDirectory, "/", filename, ".tar"}

				log.Info("Uploading to GCS: ", target)
				UploadGCS(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
				fullCompleteFile := []string{*completeDirectory, "/", filename, ".tar"}

				err = os.Rename(strings.Join(fullStagingFile, ""), strings.Join(fullCompleteFile, ""))

				if err != nil {
					fmt.Println(err)
					return
				}

			case "SESSION-ABORT":
				captureDirectory := jsonParsed.Path("data.path").Data().(string)

				fmt.Printf("Deleting (recursively) %v", captureDirectory)
				os.RemoveAll(captureDirectory)
				os.Exit(0)
			default:
				// do nothing for now.
				fmt.Printf("We did not see a valid status. No action taken")
				os.Exit(0)
			}
			os.Exit(0)
		}
	}

	// detect
	fmt.Println("HI")
	if *pub != "" && *message != "" {
		msg := namedpiper.Msg{*message}
		log.Info("Sending to: ", *pub, msg.String())

		err := namedpiper.Send(&msg, *pub)
		if err != nil {
			fmt.Println(err)
		}
		//os.Exit(0)
	}

}
