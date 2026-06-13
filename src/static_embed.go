package main

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"fnproxy/config"
)

//go:embed static
var embeddedStaticFiles embed.FS

func newStaticFileServer() http.Handler {
	staticFS, err := fs.Sub(embeddedStaticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(staticFS))
}

// injectWebRootMiddleware 注入 WebRoot 到 HTML 中
func injectWebRootMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 处理所有请求，因为经过 StripPrefix 后路径可能是 /
		webRoot := config.GetRuntimeWebRoot()
		
		// 捕获响应
		buf := &bytes.Buffer{}
		capturedStatus := http.StatusOK
		capturedHeader := http.Header{}
		customWriter := &responseCaptureWriter{
			ResponseWriter: w,
			buffer:         buf,
			status:         &capturedStatus,
			header:         &capturedHeader,
		}
		
		next.ServeHTTP(customWriter, r)
		
		// 如果缓冲区有内容且是HTML，替换 WEB_ROOT
		if buf.Len() > 0 {
			contentType := capturedHeader.Get("Content-Type")
			if strings.Contains(contentType, "text/html") || (contentType == "" && (r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html"))) {
				htmlContent := buf.String()
				if strings.Contains(htmlContent, "window.WEB_ROOT = ''") {
					// 替换 window.WEB_ROOT = '' 为实际值
					replacement := "window.WEB_ROOT = '" + webRoot + "'"
					htmlContent = strings.Replace(htmlContent, "window.WEB_ROOT = ''", replacement, 1)
					
					// 写入响应头
					for k, v := range capturedHeader {
						for _, val := range v {
							w.Header().Set(k, val)
						}
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(htmlContent)))
					w.WriteHeader(capturedStatus)
					io.WriteString(w, htmlContent)
					return
				}
			}
		}
		
		// 如果不是HTML或没有替换，直接返回原始响应
		for k, v := range capturedHeader {
			for _, val := range v {
				w.Header().Set(k, val)
			}
		}
		w.WriteHeader(capturedStatus)
		if buf.Len() > 0 {
			w.Write(buf.Bytes())
		}
	})
}

// responseCaptureWriter 捕获响应内容
type responseCaptureWriter struct {
	http.ResponseWriter
	buffer *bytes.Buffer
	status *int
	header *http.Header
}

func (w *responseCaptureWriter) Write(b []byte) (int, error) {
	return w.buffer.Write(b)
}

func (w *responseCaptureWriter) WriteHeader(statusCode int) {
	*w.status = statusCode
}

func (w *responseCaptureWriter) Header() http.Header {
	return *w.header
}
