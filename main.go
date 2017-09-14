package main

import (
	"flag"
	"fmt"
	"github.com/Jeffail/gabs"
	log "github.com/Sirupsen/logrus"
	"github.com/tzmartin/namedpiper"
	"os"
	"os/signal"
	"syscall"
)

var (
	pub      = flag.String("pub", "", "Publish to unix named pipe (fifo)")
	sub      = flag.String("sub", "", "Subscribe to unix named pipe (fifo)")
	message  = flag.String("message", "", "JSON encoded string")
	FIFO_DIR = flag.String("dir", "/tmp/pipes", "FIFO directory absolute path")
)

// Create a new instance of the logger. You can have any number of instances.
// var log = logrus.New()

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
	deleteFile(fmt.Sprintf("%s/%s", *FIFO_DIR, *sub))
}

func init() {
	log.SetFormatter(&log.TextFormatter{})
}

// This is where we can maintain the white list of files to grab out of a session
func fileWhiteListHandler(path string) string{
fmt.Println("Inspecting:  ",path)
 return path
}

func gzipHandler(path string) string {
	fmt.Println("compressing:  ",path)
	return path
}

// this will need to both upload and then read the md5Hash upon response to ensure a complete upload
func upload(file string) {
	fmt.Println("uploading:  ",file)

}

func main() {
	print("\033[H\033[2J")
	flag.Parse()

	fmt.Println("\nDARI Connect")
	fmt.Println("Version 0.0.1")
	fmt.Println("Copyright (c) 2017 Scientific Analytics, Inc.")
	fmt.Println("")

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

	// detect
	if *pub != "" {
		msg := namedpiper.Msg{*message}
		log.Info("Sending to: ", *pub, msg.String())

		err := namedpiper.Send(&msg, *pub)
		if err != nil {
			fmt.Println(err)
		}
	}

	if *sub != "" {
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
			//log.Info(msg.String())
			jsonParsed, _ := gabs.ParseJSON([]byte(msg.String()))

			  status :=  jsonParsed.Path("status").Data()
				capture_directory  :=  jsonParsed.Path("data.path").Data().(string)

					switch statusState := status; statusState {
					case "REQUEST-NEW-SESSION":
						fmt.Println("New Session Acknowledged. No Action to be taken.")
					case "SESSION-COMPLETE":
						 filesToCompress := fileWhiteListHandler(capture_directory)
						 uploadFile := gzipHandler(filesToCompress)
						 upload(uploadFile)
					case "SESSION-PARTIAL":

					case "SESSION-ABORT":
						fmt.Printf("Deleting (recursively) %v",capture_directory)
						os.RemoveAll(capture_directory)
						

					default:
						// do nothing for now.
						fmt.Printf("We did not see a valid status. No action taken")
					}
				//}
			//}

		}
	}

	if *sub == "" && *pub == "" {
		fmt.Println("No commands. Refer to -help")
	}

}
