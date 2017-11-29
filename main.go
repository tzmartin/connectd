package main

import (
	"archive/tar"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/websocket"

	"github.com/Jeffail/gabs"
	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
)

var (
	appname           = "connectd"
	version           = "0.1.8"
	versionFlag       = flag.Bool("version", false, "")
	verbose           = flag.Bool("verbose", false, "Display banner and show logs")
	addrFlag          = flag.String("port", ":50555", "server address:port")
	apiEndpoint       = flag.String("apigateway", "", "API Gateway endpoint")
	apiKey            = flag.String("apikey", "", "API key")
	gcsBucket         = flag.String("gcsBucket", "", "GCS session ingest bucket")
	pub               = flag.String("pub", "dariconnect", "Publish to unix named pipe (fifo)")
	sub               = flag.String("sub", "dariconnect", "Subscribe to unix named pipe (fifo). Defaults to dariconnect")
	message           = flag.String("message", "", "JSON encoded string")
	FIFO_DIR          = flag.String("dir", "/tmp/pipes", "FIFO directory absolute path")
	completeDirectory = flag.String("complete_dir", "/home/dari/Desktop/CaptureData/.Connect/HTTP_Completed", "directory to stash completed files")
	stagingDirectory  = flag.String("staging_dir", "/home/dari/Desktop/CaptureData/.Connect/HTTP_Staging", "directory to stash tar files upon creation")
	errorDirectory    = flag.String("error_dir", "/home/dari/Desktop/CaptureData/.Connect/HTTP_Error", "directory to stash error files")
	kioskSessionDir   = flag.String("kiosk_session_dir", "/home/dari/Desktop/CaptureData/.Connect/requests", "directory to save Kiosk session configuration as a JSON file")
)

type payload struct {
	// the json tag means this will serialize as a lowercased field
	Status  string `json:"status"`
	Message string `json:"data"`
}

// transport is an http.RoundTripper that keeps track of the in-flight
// request and implements hooks to report HTTP tracing events.
type transport struct {
	current *http.Request
}

// Session A model for session
type NewSessionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Version string `json:"version"`
	Time    string `json:"time"`
	Data    struct {
		SessionGUID string `json:"session-guid"`
		PersonMRN   string `json:"person-mrn"`
		Protocol    string `json:"protocol"`
		Fname       string `json:"fname"`
		Lname       string `json:"lname"`
		UploadPath  string `json:"upload_path"`
	} `json:"data"`
}

var wsCtx websocket.Conn
var dbFile []byte

func check(e error) {
	if e != nil {
		fmt.Print(e, "/n")
	}
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

// example Read table with sqlite3
// Be sure to read this: https://github.com/mattn/go-sqlite3#faq
// you'll also need to change sql.db to the actual sqlite file location ( I think )

func getProtocolFile(db *sql.DB) []TestItem {
	var s NullString
    err := db.QueryRow("SELECT file FROM protocols WHERE protocol_id=?", id).Scan(&s)
  
    if s.Valid {
       // use s.String
    } else {
       // NULL value
    }
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

func setGuidStatus(guid string, ws *websocket.Conn) {
	dat, err := ioutil.ReadFile(os.Getenv("HOME") + "/.dari-connect/db.status.json")
	check(err)
	dbFile, _ := gabs.ParseJSON([]byte(string(dat)))

	// fmt.Println("OKOKOKOK")
	// fmt.Println(dbFile.Path("sessions.guid").String())

	sessions, _ := dbFile.Path("sessions").Children()
	for _, session := range sessions {
		if session.Path("guid").Data() == guid {
			session.Set("Foobar", "status")
			fmt.Println(session.Data())
		}
	}
	err = ioutil.WriteFile(os.Getenv("HOME")+"/.dari-connect/db.json", dbFile.Bytes(), 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func wsUrlSchemeHandler(ws *websocket.Conn) {
	fmt.Println("Request received")
	// connection
	// m2 := payload{
	// 	Status:  "200",
	// 	Message: "{\"message\":\"connected\"}",
	// }
	// Write
	// err := websocket.JSON.Send(ws, m2)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	fmt.Fprintf(ws, "connectd v%s - random %d", version, rand.Int())

	// Read
	// msg := ""
	// err := websocket.Message.Receive(ws, &msg)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Printf("%s\n", msg, ws)
}

func wsDataHandler(ws *websocket.Conn) {
	wsCtx = *ws

	// Send connection confirmation
	websocket.JSON.Send(ws, payload{
		Status:  "200",
		Message: "{\"message\":\"connected\"}",
	})

	// fmt.Println("----BLAHBLAH---")
	// fmt.Println(dbFile)
	// fmt.Println("-------")

	// Client connected
	defer ws.Close()
	fmt.Println("Client Connected", ws)
	for {
		// Read
		msg := ""
		err := websocket.Message.Receive(ws, &msg)
		if err != nil {
			fmt.Printf("Websocket closed: %s\n", err.Error())
			return
		}

		jsonParsed, _ := gabs.ParseJSON([]byte(msg))
		status := jsonParsed.Path("status").Data()

		// wsData := jsonParsed.Path("data").Data()

		fmt.Println("-------")
		fmt.Println(msg)
		fmt.Println("-------")

		// Check status property in JSON object
		switch statusState := status; statusState {
		case "API-NEW-SESSION":
			fmt.Println("NEW SESSION")

			newSessionJSON := map[string]interface{}{
				"action": "session-create",
				"data":   map[string]interface{}{},
			}
			if jsonParsed.Exists("data", "height") {
				newSessionJSON["data"].(map[string]interface{})["height"] = jsonParsed.Path("data.height").Data()
			}
			if jsonParsed.Exists("data", "weight") {
				newSessionJSON["data"].(map[string]interface{})["weight"] = jsonParsed.Path("data.weight").Data()
			}
			if jsonParsed.Exists("data", "fname") {
				if jsonParsed.Path("data.fname").Data() != "" {
					newSessionJSON["data"].(map[string]interface{})["fname"] = jsonParsed.Path("data.fname").Data()
				}
			}
			if jsonParsed.Exists("data", "lname") {
				if jsonParsed.Path("data.lname").Data() != "" {
					newSessionJSON["data"].(map[string]interface{})["lname"] = jsonParsed.Path("data.lname").Data()
				}
			}
			if jsonParsed.Exists("data", "uid") {
				newSessionJSON["data"].(map[string]interface{})["uid"] = jsonParsed.Path("data.uid").Data()
			}
			if jsonParsed.Exists("data", "unit_mode") {
				newSessionJSON["data"].(map[string]interface{})["unit_mode"] = jsonParsed.Path("data.unit_mode").Data()
			}
			if jsonParsed.Exists("data", "protocol") {
				newSessionJSON["data"].(map[string]interface{})["protocol"] = jsonParsed.Path("data.protocol").Data()
			}

			b, err := json.Marshal(newSessionJSON)
			if err != nil {
				fmt.Println("error:", err)
			}
			fmt.Println("THISSHOULDWORK")
			fmt.Println(string(b))

			body := strings.NewReader(string(b))
			fmt.Println(body)

			req, err := http.NewRequest("POST", *apiEndpoint, body)
			if err != nil {
				fmt.Println(err)
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("apikey", *apiKey)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(resp.Status)
			bodyResp, err := ioutil.ReadAll(resp.Body)
			var s = new(NewSessionResponse)
			err = json.Unmarshal(bodyResp, &s)
			if err != nil {
				fmt.Println("whoops:", err)
			}
			fmt.Println("API Response: SessionID: \n", string(bodyResp))
			if err != nil {
			}

			if resp.StatusCode == 201 {
				if s.Data.SessionGUID != "" {

					// Save Kiosk session config file to session_dir
					fmt.Println("Creating file")
					fmt.Println(*kioskSessionDir)

					// kioskConfigStruct
					kioskConfig := map[string]string{
						"source":    "connect",
						"status":    "REQUEST-NEW-SESSION",
						"protocol":  "",
						"uid":       "",
						"guid":      fmt.Sprintf("%s", s.Data.SessionGUID),
						"height":    fmt.Sprintf("%v", jsonParsed.Path("data.height").Data()),
						"weight":    fmt.Sprintf("%v", jsonParsed.Path("data.weight").Data()),
						"unit_mode": "",
						"fname":     "",
						"lname":     "",
						"prompt":    "0",
					}
					if s.Data.PersonMRN != "" {
						kioskConfig["uid"] = s.Data.PersonMRN
					}
					if jsonParsed.Exists("data", "protocol") {
						kioskConfig["protocol"] = fmt.Sprintf("%s", jsonParsed.Path("data.protocol").Data())
					}
					if jsonParsed.Path("data.fname").String() != "{}" {
						kioskConfig["fname"] = fmt.Sprintf("%s", jsonParsed.Path("data.fname").Data())
					}
					if jsonParsed.Path("data.lname").String() != "{}" {
						kioskConfig["lname"] = fmt.Sprintf("%s", jsonParsed.Path("data.lname").Data())
					}
					if jsonParsed.Exists("data", "unit_mode") {
						kioskConfig["unit_mode"] = fmt.Sprintf("%v", jsonParsed.Path("data.unit_mode").Data())
					}

					/*
						Required structure
						{
							fname: 'bar',
							guid: 'a111ef90-0798-4d13-a7af-e0f86b0381c5',
							height: '2.54',
							lname: 'baz',
							protocol: 'EXOS MQ',
							source: 'connect',
							uid: '3992062a-cee2-4b44-abde-16fa15e55226',
							unit_mode: 'metric',
							weight: '4.41'
						}
					*/
					// kioskConfig["fname"] := fname
					// kioskConfig["lname"] = lname

					kioskConfigJSON, _ := json.Marshal(kioskConfig)
					fmt.Println("Kiosk Config")
					fmt.Println(string(kioskConfigJSON))

					// get num files in dir
					files, _ := ioutil.ReadDir(*kioskSessionDir)

					// d1 := []byte(string(kioskConfigJSON))
					err = ioutil.WriteFile(fmt.Sprintf("%v/kiosk_session_%v.json", *kioskSessionDir, len(files)), kioskConfigJSON, 0644)
					if err != nil {
						fmt.Println(err)
						return
					}

					// Send socket request
					err = websocket.JSON.Send(ws, payload{
						Status:  "201",
						Message: string(kioskConfigJSON),
					})
					fmt.Println("\nSent 201 - session created")

					var cmdStr [2]string

					// Launch Kiosk!  When Kiosk launches it will look in a specific folder for a kiosk_session.json
					if runtime.GOOS == "darwin" {
						cmdStr[0] = "say"
						cmdStr[1] = "Session created. Ready to start kiosk."
					} else {
						cmdStr[0] = "/usr/local/sbin/dari"
						cmdStr[1] = ""
					}

					// Deprecate this due to bug in Command. Switching to node.
					// DARI Connect will prompt for user to spawn the kiosk
					// fmt.Printf("\nExecuting command: " + cmdStr[0] + cmdStr[1])
					// cmd := exec.Command(cmdStr[0], cmdStr[1])
					// cmd.Start()

					// Save DB file
					// setGuidStatus(s.Data.SessionGUID, "Ready", ws)

					// // Send socket request
					err = websocket.JSON.Send(ws, payload{
						Status:  "202",
						Message: "{\"message\":\"Ready to start\"}",
					})
					fmt.Println("\nSent 202 - Ready to start kiosk")

				} else {
					// Send socket request
					err = websocket.JSON.Send(ws, payload{
						Status:  "401",
						Message: "{\"message\":\"Unable to generate session guid. Try again or contact support.\"}",
					})
					if err != nil {
						fmt.Println(err)
					}
					fmt.Println("\nSent 401 - " + resp.Status)
				}
			} else {
				// Send socket request
				err = websocket.JSON.Send(ws, payload{
					Status:  "400",
					Message: "{\"message\":\"" + resp.Status + "\"}",
				})
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("\nSent 400 - " + resp.Status)
			}
			defer resp.Body.Close()

			// os.Exit(0)
			break

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
			break

		case "SESSION-ABORT":
			captureDirectory := jsonParsed.Path("data.path").Data().(string)

			fmt.Printf("Deleting (recursively) %v", captureDirectory)
			os.RemoveAll(captureDirectory)
			break

		case "HEALTHCHECK":
			// Send socket request
			err = websocket.JSON.Send(ws, payload{
				Status:  "200",
				Message: "{\"version\":\"" + version + "\"}",
			})
			if err != nil {
				fmt.Println(err)
			}
			break

		default:
			// do nothing for now.
			// fmt.Printf("We did not see a valid status. No action taken")
			// os.Exit(0)
		}
	}
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
	log.Info("Uploading to GCS: ", filepath, filename, wsCtx)

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
	req, err := http.NewRequest("POST", "https://www.googleapis.com/upload/storage/v1/b/"+*gcsBucket+"/o?uploadType=media&name="+filename, fileToUpload)
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
	fmt.Printf("Status Code: %v\n", resp.StatusCode)

	if resp.StatusCode == 200 {
		println("Initial checksum was: ", md5Checksum)
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println("post:\n", string(body))
		if err != nil {
		}

		// TODO: clean up this seems rediculous
		responseParsed, _ := gabs.ParseJSON([]byte(string(body)))
		gcsMd5Base64 := responseParsed.Path("md5Hash").Data()
		var gcsMd5Base64String = gcsMd5Base64.(string)
		gcsMd5Hex, err := base64.StdEncoding.DecodeString(gcsMd5Base64String)
		if err != nil {
			log.Fatal("error:", err)
		}
		fmt.Println("gcs hash is", gcsMd5Hex)

		if wsCtx.IsServerConn() {
			err = websocket.JSON.Send(&wsCtx, payload{
				Status:  "200",
				Message: "{\"message\":\"success\", \"gcsMd5Hex\":\"" + string(gcsMd5Hex) + "\"\"}",
			})
			check(err)
		}

		// Move to completed folder
		fullCompleteFile := []string{*completeDirectory, "/", filename}
		err = os.Rename(fileToUpload.Name(), strings.Join(fullCompleteFile, ""))
		if err != nil {
			fmt.Println(err)
		}
	}
	if resp.StatusCode == 401 {
		// Unauthorized
		fmt.Println("Unauthorized")
		// Send connection confirmation

		if wsCtx.IsServerConn() {
			err := websocket.JSON.Send(&wsCtx, payload{
				Status:  "401",
				Message: "{\"message\":\"Unauthorized. This file has already been processed.\"}",
			})
			check(err)
		}

		// Move to error folder
		fullCompleteFile := []string{*errorDirectory, "/", filename}
		err = os.Rename(fileToUpload.Name(), strings.Join(fullCompleteFile, ""))
		if err != nil {
			fmt.Println(err)
		}
	}

	defer resp.Body.Close()
	return
}

// func fileWatchHandler() {
// 	fmt.Println("stagingDirectory is: ", *stagingDirectory)

// 	// fmt.Println(reflect.TypeOf(uploadFile))
// 	filename = filepath.Base(captureDirectory)
// 	target := filepath.Join(*stagingDirectory, fmt.Sprintf("%s.tar", filename))

// Upload to GCS
// UploadGCS(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
// fullCompleteFile := []string{*completeDirectory, "/", filename, ".tar"}

// err = os.Rename(target, strings.Join(fullCompleteFile, ""))

// if err != nil {
// 	fmt.Println(err)
// 	return
// }
// }

// KioskSessionWatcher Watch for new session files from Kiosk
func KioskSessionWatcher() {
	if *verbose == true {
		fmt.Println("Watching for new files: " + *stagingDirectory)
	}
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
				// log.Println("event:", event)
				if event.Op&fsnotify.Create == fsnotify.Create {
					// assume it's a SESSION COMPLETE/PARTIAL from Kiosk
					log.Println("Found new file: " + path.Base(event.Name))
					filename := fmt.Sprintf("%s", path.Base(event.Name))

					// Upload to GCS
					UploadGCS(*stagingDirectory, filename)
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(*stagingDirectory)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

// dbWatcher Watches for db changes
func dbWatcher() {
	if *verbose == true {
		fmt.Println("Watching database: " + os.Getenv("HOME") + "/.dari-connect/db.json")
	}
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
					// assume it's a SESSION COMPLETE/PARTIAL from Kiosk
					log.Println("Write file: " + path.Base(event.Name))
					// filename := fmt.Sprintf("%s", path.Base(event.Name))
					dat, err := ioutil.ReadFile(os.Getenv("HOME") + "/.dari-connect/db.json")
					check(err)
					dbFile, _ := gabs.ParseJSON([]byte(string(dat)))

					status := dbFile.Path("machineID").String()
					fmt.Println(status)
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(os.Getenv("HOME") + "/.dari-connect/db.json")
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

func main() {
	print("\033[H\033[2J")
	flag.Parse()

	// Read current version from file
	// versiondat, err := ioutil.ReadFile("version")
	// check(err)

	// add double dash flag parser
	// version := string(versiondat)

	// if *versionFlag == true {
	// 	fmt.Println(version)
	// 	os.Exit(0)
	// }

	if *verbose == true {
		fmt.Printf("%s\n", appname)
		fmt.Println("Version " + version)
		fmt.Println("GOOS: " + runtime.GOOS)
		fmt.Println("Home dir: " + os.Getenv("HOME"))
		fmt.Printf("pid: %d\n", os.Getpid())
		fmt.Println("Copyright (c) 2017 Scientific Analytics, Inc.")
		fmt.Println("")
		fmt.Println("---FLAGS---")
		flag.Visit(func(a *flag.Flag) {
			fmt.Println(a.Name, "=", a.Value)
		})
		fmt.Println("-----------")
	}
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

		// DEPRECATED
		// log.Info(*message)
		jsonParsed, _ := gabs.ParseJSON([]byte(*message))

		status := jsonParsed.Path("status").Data()

		// // Check status property in JSON object
		switch statusState := status; statusState {

		case "API-NEW-SESSION":
			fmt.Println("NEW SESSION")

			// sessionConfigJSON, _ := json.Marshal(sessionConfig)
			// fmt.Println(string(kioskConfigJSON))

			body := strings.NewReader(`{"action":"session-create","data":{"height":"70","weight":"205","fname":"Jason","lname":"Nelson","uid":"TESTDARI02"}}`)
			req, err := http.NewRequest("POST", "http://130.211.176.189/api/v1/session", body)
			if err != nil {
				// handle err
				fmt.Println(err)
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// handle err
				fmt.Println(err)
			}

			fmt.Println(resp.Status)
			bodyResp, err := ioutil.ReadAll(resp.Body)
			fmt.Println(bodyResp)
			var s = new(NewSessionResponse)
			err = json.Unmarshal(bodyResp, &s)
			if err != nil {
				fmt.Println("whoops:", err)
			}
			fmt.Println("API Response: SessionID: \n", string(bodyResp))

			fmt.Println("done")
			fmt.Println(resp.Body)
			defer resp.Body.Close()

			// Save Kiosk session config file to session_dir
			fmt.Println("Creating file")
			fmt.Printf(*kioskSessionDir)
			d1 := []byte("{\"source\": \"connect\",\"status\":\"REQUEST-NEW-SESSION\",\"protocol\":\"EXOS MQ\",\"uid\":\"1111-some-uid\",\"guid\":\"000000-123-123sadf-asdfsadf-asdfsdaf\",\"height\":\"70\",\"weight\":\"180\"}")
			err = ioutil.WriteFile(*kioskSessionDir+"/kiosk_session.json", d1, 0644)
			if err != nil {
				fmt.Println(err)
				return
			}

			// Launch Kiosk!  When Kiosk launches it will look in a specific folder for a kiosk_session.json
			// /usr/local/sbin/dari
			cmd := exec.Command("gnome-terminal -e dari")
			cmd.Start()
			os.Exit(0)

		case "SESSION-PARTIAL":

			// Deprecated
			// captureDirectory := jsonParsed.Path("data.path").Data().(string)
			// fmt.Println("stagingDirectory is: ", *stagingDirectory)
			// err := tarit(captureDirectory, *stagingDirectory)
			// if err != nil {
			// 	log.Info("was unable to tar file, captureDirectory:", captureDirectory, " stagingDirectory  ", *stagingDirectory)

			// }
			// filename := filepath.Base(*stagingDirectory)

			// // fmt.Println(reflect.TypeOf(uploadFile))
			// filename = filepath.Base(captureDirectory)
			// target := filepath.Join(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
			// fullStagingFile := []string{captureDirectory, "/", filename, ".tar"}

			// log.Info("Uploading to GCS: ", target)
			// UploadGCS(*stagingDirectory, fmt.Sprintf("%s.tar", filename))
			// fullCompleteFile := []string{*completeDirectory, "/", filename, ".tar"}

			// err = os.Rename(strings.Join(fullStagingFile, ""), strings.Join(fullCompleteFile, ""))

			// if err != nil {
			// 	fmt.Println(err)
			// 	return
			// }

		case "SESSION-ABORT":
			// captureDirectory := jsonParsed.Path("data.path").Data().(string)

			// fmt.Printf("Deleting (recursively) %v", captureDirectory)
			// os.RemoveAll(captureDirectory)
			os.Exit(0)
		default:
			// do nothing for now.
			fmt.Printf("No action taken. Message is depcrecated")
			os.Exit(0)
		}
	}

	// detect
	if *message == "" {
		// Start socket server
		go func() {
			if *verbose == true {
				fmt.Println("Websocket server: http://127.0.0.1" + *addrFlag + "/data")
			}
			http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "connectd v%s - random %d", version, rand.Int())
			}))
			http.Handle("/data", websocket.Handler(wsDataHandler))
			http.Handle("/urlscheme", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "YAY %s", r.RequestURI)
			}))
			err := http.ListenAndServe(*addrFlag, nil)
			if err != nil {
				log.Fatal(err)
			}
		}()

		// Watch database file
		// go dbWatcher()

		// Watch for new Kiosk files
		KioskSessionWatcher()

	}

}
