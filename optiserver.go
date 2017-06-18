package optiserver

import (
	"bufio"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/buaazp/fasthttprouter"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/mailru/easyjson"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"
)

type Application struct {
	Config          *Configuration
	Logger          *zap.Logger
	Router          *fasthttprouter.Router
	server          *http.Server
	NotFoundHandler *http.HandlerFunc
	ErrorHandler    *http.HandlerFunc
}

const (
	// ContentBinary header value for binary data.
	ContentBinary = "application/octet-stream"
	// ContentJSON header value for JSON data.
	ContentJSON = "application/json"
	// ContentJSONP header value for JSONP data.
	ContentJSONP = "application/javascript"
	// ContentLength header constant.
	ContentLength = "Content-Length"
	// ContentText header value for Text data.
	ContentText = "text/plain"
	// ContentType header constant.
	ContentType = "Content-Type"
	// ContentXML header value for XML data.
	ContentXML = "text/xml"
)

type Configuration struct {
	Debug      bool   `yaml:"Debug"`
	TLS        bool   `yaml:"TLS"`
	DomainName string `yaml:"DomainName"`
	HTTPPort   int    `yaml:"HTTPPort"`
	HTTPSPort  int    `yaml:"HTTPSPort"`
	Host       string `yaml:"Host"`
	ChainPath  string `yaml:"Chain"`
	KeyPath    string `yaml:"Key"`
}

func DefaultConfiguration() Configuration {
	return Configuration{
		Debug:      true,
		TLS:        false,
		DomainName: "",
		HTTPPort:   8080,
		HTTPSPort:  8443,
		Host:       "0.0.0.0",
		ChainPath:  "",
		KeyPath:    "",
	}
}

// New creates and returns a fresh empty optiserver *Application instance.
func New() (*Application, error) {
	config := DefaultConfiguration()
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	app := &Application{
		Config: &config,
		Logger: logger,
		Router: fasthttprouter.New(),
	}
	return app, nil
}

func (a *Application) Run() error {
	a.Logger.Info("Starting Server")

	// the listener for unencrypted traffic
	if a.Config.TLS == false {
		err2 := http.ListenAndServe(a.Config.Host+":"+strconv.Itoa(a.Config.HTTPPort), fasthttpadaptor.NewHTTPHandler(a.Router.Handler))
		if err2 != nil {
			return err2
		}
		// err := fasthttp.ListenAndServe(a.Config.Host+":"+strconv.Itoa(a.Config.HTTPPort), a.Router.Handler)
		// if err != nil {
		// 	return err
		// }
	} else {
		err := fasthttp.ListenAndServe(a.Config.Host+":"+strconv.Itoa(a.Config.HTTPPort), a.Router.Handler)
		if err != nil {
			return err
		}
		err = h2quic.ListenAndServeQUIC(a.Config.Host+":"+strconv.Itoa(a.Config.HTTPSPort), "/path/to/cert/chain.pem", "/path/to/privkey.pem", fasthttpadaptor.NewHTTPHandler(a.Router.Handler))
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Application) ReverseProxy(upstreams []string) func(ctx *fasthttp.RequestCtx) {
	var lbc fasthttp.LBClient
	for _, addr := range upstreams {
		c := &fasthttp.HostClient{
			Addr: addr,
		}
		lbc.Clients = append(lbc.Clients, c)
	}
	return func(ctx *fasthttp.RequestCtx) {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.SetRequestURIBytes(ctx.URI().FullURI())
		if err := lbc.Do(req, resp); err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
		}
		if resp.StatusCode() != fasthttp.StatusOK {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.Logger().Printf("unexpected status code: %d. Expecting %d", resp.StatusCode(), fasthttp.StatusOK)
		}
	}
}

func (a *Application) StaticFolder(folderpath string, cacheTimeSeconds uint64) func(w http.ResponseWriter, r *http.Request) {
	const modifiedLayout = "Mon, 2 Jan 2006 15:04:05 MST"
	return func(w http.ResponseWriter, r *http.Request) {
		filepath := path.Join(folderpath, r.URL.RawPath)
		stat, err := os.Stat(filepath)
		if err != nil {
			a.NotFoundHandler.ServeHTTP(w, r)
			return // file not found
		}

		// set cache header
		w.Header().Add("Cache-Control", "max-age="+strconv.FormatUint(cacheTimeSeconds, 10))

		// check if user has the file already
		if modified := r.Header.Get("If-Modified-Since"); len(modified) > 0 {
			if ifTime, err := time.Parse(modifiedLayout, modified); err == nil {
				if stat.ModTime().Equal(ifTime) {
					w.WriteHeader(http.StatusNotModified)
					return // user has the file already
				}
			}
		}
		// set mimetype
		mimetype := mime.TypeByExtension(path.Ext(r.URL.RawPath))
		if len(mimetype) > 0 {
			w.Header().Add("Content-Type", mimetype)
		}

		// set Last Modified
		w.Header().Add("Last-Modified", stat.ModTime().Format(modifiedLayout))

		file, err2 := os.Open(filepath)
		if err2 != nil {
			a.ErrorHandler.ServeHTTP(w, r)
			return // error opening file
		}
		defer file.Close()
		_, err = io.Copy(w, file)
		if err != nil {
			a.ErrorHandler.ServeHTTP(w, r)
			return // error opening file
		}

	}
}

func Binary(ctx *fasthttp.RequestCtx, statusCode int, data *[]byte) {
	ctx.SetContentType(ContentBinary)
	ctx.SetStatusCode(statusCode)
	ctx.Write(*data)
}
func TextByte(ctx *fasthttp.RequestCtx, statusCode int, data *[]byte) {
	ctx.SetContentType(ContentText)
	ctx.SetStatusCode(statusCode)
	ctx.Write(*data)
}
func TextString(ctx *fasthttp.RequestCtx, statusCode int, data *string) {
	ctx.SetContentType(ContentText)
	ctx.SetStatusCode(statusCode)
	ctx.WriteString(*data)
}
func JSON(ctx *fasthttp.RequestCtx, statusCode int, data interface{}) {
	ctx.SetContentType(ContentJSON)
	ctx.SetStatusCode(statusCode)
	ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
		if easydata, ok := data.(easyjson.Marshaler); ok {
			easyjson.MarshalToWriter(easydata, w)
			return
		}
		encoder := json.NewEncoder(w)
		encoder.Encode(data)
	})
}
