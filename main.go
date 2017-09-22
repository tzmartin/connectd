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
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/websocket"

	"github.com/Jeffail/gabs"
	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
)

var (
	version           = "0.0.6"
	addrFlag          = flag.String("port", ":5555", "server address:port")
	pub               = flag.String("pub", "dariconnect", "Publish to unix named pipe (fifo)")
	sub               = flag.String("sub", "dariconnect", "Subscribe to unix named pipe (fifo). Defaults to dariconnect")
	message           = flag.String("message", "", "JSON encoded string")
	FIFO_DIR          = flag.String("dir", "/tmp/pipes", "FIFO directory absolute path")
	completeDirectory = flag.String("complete_dir", "", "directory to stash completed files")
	stagingDirectory  = flag.String("staging_dir", "", "directory to stash tar files upon creation")
	kioskSessionDir   = flag.String("kiosk_session_dir", "", "directory to save Kiosk session configuration as a JSON file")
)

type payload struct {
	// the json tag means this will serialize as a lowercased field
	Message string `json:"data"`
}

// transport is an http.RoundTripper that keeps track of the in-flight
// request and implements hooks to report HTTP tracing events.
type transport struct {
	current *http.Request
}

// RoundTrip wraps http.DefaultTransport.RoundTrip to keep track
// of the current request.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.current = req
	return http.DefaultTransport.RoundTrip(req)
}

// GotConn prints whether the connection has been used previously
// for the current request.
func (t *transport) GotConn(info httptrace.GotConnInfo) {
	fmt.Printf("Connection reused for %v? %v\n", t.current.URL, info.Reused)
}

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

func wsDataHandler(ws *websocket.Conn) {
	m2 := payload{"Thanks for the message!"}
	websocket.JSON.Send(ws, m2)
}

func wsRootHandler(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadFile("README.md")
	if err != nil {
		fmt.Println("Could not open file.", err)
	}
	fmt.Fprintf(w, "%s", content)
}

// UploadGCS Upload a file to Google Cloud Storage
func UploadGCS(filepath, filename string) (err error) {
	log.Info("Uploading to GCS: ", filepath, filename)
	t := &transport{}
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
	trace := &httptrace.ClientTrace{
		GotConn: t.GotConn,
		ConnectStart: func(network, addr string) {
			fmt.Println("Dial start")
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Println("Dial done")
		},
		GotFirstResponseByte: func() {
			fmt.Println("First response byte")
		},
		WroteHeaders: func() {
			fmt.Println("Wrote headers")
		},
		WroteRequest: func(wr httptrace.WroteRequestInfo) {
			fmt.Println("Wrote request", wr)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Transport: t}

	resp, err := client.Do(req)
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

// KioskSessionWatcher Watch for new session files from Kiosk
func KioskSessionWatcher() {
	fmt.Println("Watching for new files: " + *kioskSessionDir)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("modified file:", event.Name)
					fmt.Sprintf(event.Name)
					if event.Name == "CREATE" {
						// assume it's a SESSION COMPLETE/PARTIAL from Kiosk
					}
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(*kioskSessionDir)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

func main() {
	print("\033[H\033[2J")
	flag.Parse()
	fmt.Println("\nDARI Connect")
	fmt.Println("Version " + version)
	fmt.Printf("pid: %d\n", os.Getpid())
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

	// JSON payload exists
	if *message != "" {
		log.Info(*message)
		jsonParsed, _ := gabs.ParseJSON([]byte(*message))

		status := jsonParsed.Path("status").Data()

		// Check status property in JSON object
		switch statusState := status; statusState {
		case "API-NEW-SESSION":
			fmt.Println("NEW SESSION")

			body := strings.NewReader(*message)
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
			fmt.Println("done")
			fmt.Println(resp.Body)
			defer resp.Body.Close()

			// Save Kiosk session config file to session_dir
			fmt.Println("Creating file")
			fmt.Printf(*kioskSessionDir)
			d1 := []byte("{\"source\": \"connect\",\"status\":\"REQUEST-NEW-SESSION\",\"uid\":\"1111-some-uid\",\"uuid\":\"000000-123-123sadf-asdfsadf-asdfsdaf\",\"height\":\"70\",\"weight\":\"180\"}")
			err = ioutil.WriteFile(*kioskSessionDir+"/kiosk_session.json", d1, 0644)
			if err != nil {
				fmt.Println(err)
				return
			}

			// Launch Kiosk!  When Kiosk launches it will look in a specific folder for a kiosk_session.json
			// exec('dari')
			// Possibly disown this process
			// os.Exit(0)

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

			// Upload to GCS
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
	}

	// detect
	if *message == "" {
		// Start socket server
		go func() {
			fmt.Println("Websocket server: http://127.0.0.1" + *addrFlag + "/data")
			http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "connectd v%s - random %d", version, rand.Int())
			}))
			http.Handle("/data", websocket.Handler(wsDataHandler))
			err := http.ListenAndServe(*addrFlag, nil)
			if err != nil {
				log.Fatal(err)
			}
		}()

		// Watch for new Kiosk files
		KioskSessionWatcher()
	}

}
