package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/v2/pkg/http"
	whlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	metrics "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	whmodel "github.com/slok/kubewebhook/v2/pkg/model"
	wh "github.com/slok/kubewebhook/v2/pkg/webhook"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	"github.com/urfave/cli"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

/* #nosec */
const (
	// secretsInitContainer is the default gtoken container from which to pull the 'gtoken' binary.
	gtokenInitImage = "doitintl/gtoken:latest"

	// tokenVolumeName is the name of the volume where the generated id token will be stored
	tokenVolumeName = "gtoken-volume"

	// tokenVolumePath is the mount path where the generated id token will be stored
	tokenVolumePath = "/var/run/secrets/aws/token"

	// token file name
	tokenFileName = "gtoken"

	// AWS annotation key; used to annotate Kubernetes Service Account with AWS Role ARN
	awsRoleArnKey = "amazonaws.com/role-arn"

	// application specific annotations
	tokenGenerateAnnotation = "gtoken.doit-intl.com/tokenGenerate"
	audienceAnnotation      = "gtoken.doit-intl.com/tokenAudience"
	methodAnnotation        = "gtoken.doit-intl.com/tokenMethod"
	volumePathAnnotation    = "gtoken.doit-intl.com/volumePath"
	tokenFilenameAnnotation = "gtoken.doit-intl.com/tokenFilename"

	// AWS Web Identity Token ENV
	awsWebIdentityTokenFile = "AWS_WEB_IDENTITY_TOKEN_FILE"
	awsRoleArn              = "AWS_ROLE_ARN"
	awsRoleSessionName      = "AWS_ROLE_SESSION_NAME"
)

var (
	// Version contains the current version.
	Version = "dev"
	// BuildDate contains a string with the build date.
	BuildDate = "unknown"
	// test mode
	testMode = false
)

const (
	requestsCPU    = "5m"
	requestsMemory = "10Mi"
	limitsCPU      = "20m"
	limitsMemory   = "50Mi"

	methodMetadata = "metadata"
	methodAPI      = "api"
)

type mutatingWebhook struct {
	k8sClient  kubernetes.Interface
	image      string
	pullPolicy string
	volumeName string
	volumePath string
	tokenFile  string
}

type config struct {
	generate   bool
	awsRoleArn string
	audience   string
	method     string
	volumePath string
	tokenFile  string
}

var logger *log.Logger

// Returns an int >= min, < max
func randomInt(min, max int) int {
	//nolint:gosec
	return min + rand.Intn(max-min)
}

// Generate a random string of a-z chars with len = l
func randomString(l int) string {
	if testMode {
		return strings.Repeat("0", 16)
	}
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randomInt(97, 122))
	}
	return string(bytes)
}

// Checks if a slice included a string
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func newK8SClient() (kubernetes.Interface, error) {
	kubeConfig, err := kubernetesConfig.GetConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(kubeConfig)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}

func serveMetrics(addr string) {
	logger.Infof("Telemetry on http://%s", addr)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		logger.WithError(err).Fatal("error serving telemetry")
	}
}

func handlerFor(config mutating.WebhookConfig, recorder wh.MetricsRecorder, logger *log.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config)
	if err != nil {
		logger.WithError(err).Fatal("error creating webhook")
	}

	measuredWebhook := wh.NewMeasuredWebhook(recorder, webhook)

	handler, err := whhttp.HandlerFor(whhttp.HandlerConfig{
		Webhook: measuredWebhook,
		Logger:  whlogrus.NewLogrus(log.NewEntry(logger)),
	})
	if err != nil {
		logger.WithError(err).Fatalf("error creating webhook")
	}

	return handler
}

func (mw *mutatingWebhook) getServiceAccountAnnotations(ctx context.Context, name, ns string) (map[string]string, error) {
	sa, err := mw.k8sClient.CoreV1().ServiceAccounts(ns).Get(ctx, name, metav1.GetOptions{})

	if err != nil {
		logger.WithFields(log.Fields{"service account": name, "namespace": ns}).WithError(err).Fatalf("error getting service account")
		return map[string]string{}, err
	}
	return sa.GetAnnotations(), nil
}

//nolint:gocyclo
func (c *config) parseFromAnnotations(annotations map[string]string, ignoreAnnotations []string) error {
	// parse the "amazonaws.com/role-arn" annotation.
	if !stringInSlice(awsRoleArnKey, ignoreAnnotations) {
		roleArn, ok := annotations[awsRoleArnKey]
		if ok {
			c.awsRoleArn = roleArn
			c.generate = true
		}
	}
	// parse the "gtoken.doit-intl.com/tokenGenerate" annotation.
	if !stringInSlice(tokenGenerateAnnotation, ignoreAnnotations) {
		generate, ok := annotations[tokenGenerateAnnotation]
		if ok {
			parsed, parseErr := strconv.ParseBool(generate)
			if parseErr != nil {
				err := fmt.Errorf("invalid %s: %s. %s", tokenGenerateAnnotation, generate, parseErr.Error())
				return err
			}
			if parsed {
				c.generate = parsed
			}
		}
	}
	// parse the "gtoken.doit-intl.com/tokenAudience" annotation.
	if !stringInSlice(audienceAnnotation, ignoreAnnotations) {
		audience, ok := annotations[audienceAnnotation]
		if ok {
			c.audience = audience
		}
	}
	// parse the "gtoken.doit-intl.com/tokenMethod" annotation.
	if !stringInSlice(methodAnnotation, ignoreAnnotations) {
		method, ok := annotations[methodAnnotation]
		if ok {
			if method != methodAPI && method != methodMetadata {
				err := fmt.Errorf("invalid %s: %s. Allowed values: [api, metadata]", methodAnnotation, method)
				return err
			}
			c.method = method
		}
	}
	// parse the "gtoken.doit-intl.com/volumePath" annotation.
	if !stringInSlice(volumePathAnnotation, ignoreAnnotations) {
		volumePath, ok := annotations[volumePathAnnotation]
		if ok {
			c.volumePath = volumePath
		}
	}
	// parse the "gtoken.doit-intl.com/tokenFilename" annotation.
	if !stringInSlice(tokenFilenameAnnotation, ignoreAnnotations) {
		tokenFilename, ok := annotations[tokenFilenameAnnotation]
		if ok {
			c.tokenFile = tokenFilename
		}
	}
	return nil
}

func (mw *mutatingWebhook) mutateContainers(containers []corev1.Container, annotationConfig *config) bool {
	if len(containers) == 0 {
		return false
	}
	for i, container := range containers {
		// add token volume mount
		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      mw.volumeName,
				MountPath: annotationConfig.volumePath,
			},
		}...)
		// add AWS Web Identity Token environment variables to container
		if annotationConfig.awsRoleArn != "" {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  awsWebIdentityTokenFile,
					Value: fmt.Sprintf("%s/%s", mw.volumePath, mw.tokenFile),
				},
				{
					Name:  awsRoleArn,
					Value: annotationConfig.awsRoleArn,
				},
				{
					Name:  awsRoleSessionName,
					Value: fmt.Sprintf("gtoken-webhook-%s", randomString(16)),
				},
			}...)
		}

		// update containers
		containers[i] = container
	}
	return true
}

func (mw *mutatingWebhook) mutatePod(ctx context.Context, pod *corev1.Pod, ns string, dryRun bool) error {
	// get the configuration from the Service Account annotations
	var annotationsConfig config
	annotations, err := mw.getServiceAccountAnnotations(ctx, pod.Spec.ServiceAccountName, ns)
	if err != nil {
		return err
	}
	// parse Service Account annotations
	err = annotationsConfig.parseFromAnnotations(annotations, []string{})
	if err != nil {
		logger.WithFields(log.Fields{"service account": pod.Spec.ServiceAccountName, "namespace": ns}).
			WithError(err).
			Warnf("error parsing the annotations")
	}
	// parse the Pod annotations
	err = annotationsConfig.parseFromAnnotations(pod.GetAnnotations(), []string{awsRoleArnKey})
	if err != nil {
		logger.WithFields(log.Fields{"pod": pod.Name, "namespace": ns}).
			WithError(err).
			Warnf("error parsing the annotations")
	}
	if !annotationsConfig.generate {
		logger.Debug("skipping pods with Service Account without AWS Role ARN annotation")
		return nil
	}
	// Set the volume path to default if not set
	if annotationsConfig.volumePath == "" {
		annotationsConfig.volumePath = mw.volumePath
	}
	if annotationsConfig.tokenFile == "" {
		annotationsConfig.tokenFile = mw.tokenFile
	}
	// mutate Pod init containers
	initContainersMutated := mw.mutateContainers(pod.Spec.InitContainers, &annotationsConfig)
	if initContainersMutated {
		logger.Debug("successfully mutated pod init containers")
	} else {
		logger.Debug("no pod init containers were mutated")
	}

	// mutate Pod containers
	containersMutated := mw.mutateContainers(pod.Spec.Containers, &annotationsConfig)
	if containersMutated {
		logger.Debug("successfully mutated pod containers")
	} else {
		logger.Debug("no pod containers were mutated")
	}

	if (initContainersMutated || containersMutated) && !dryRun {
		// prepend gtoken init container (as first in it container)
		pod.Spec.InitContainers = append([]corev1.Container{getGtokenContainer("generate-gcp-id-token",
			mw.image, mw.pullPolicy, mw.volumeName, false, &annotationsConfig)}, pod.Spec.InitContainers...)
		logger.Debug("successfully prepended pod init containers to spec")
		// append sidekick gtoken update container (as last container)
		pod.Spec.Containers = append(pod.Spec.Containers, getGtokenContainer("update-gcp-id-token",
			mw.image, mw.pullPolicy, mw.volumeName, true, &annotationsConfig))
		logger.Debug("successfully prepended pod sidekick containers to spec")
		// append empty gtoken volume
		pod.Spec.Volumes = append(pod.Spec.Volumes, getGtokenVolume(mw.volumeName))
		logger.Debug("successfully appended pod spec volumes")
	}

	return nil
}

func getGtokenVolume(volumeName string) corev1.Volume {
	return corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory,
			},
		},
	}
}

func getGtokenContainer(name, image, pullPolicy, volumeName string, refresh bool, annotationConfig *config) corev1.Container {
	cmd := []string{"/gtoken", fmt.Sprintf("--file=%s/%s", annotationConfig.volumePath, annotationConfig.tokenFile),
		fmt.Sprintf("--refresh=%t", refresh)}
	if annotationConfig.audience != "" {
		cmd = append(cmd, fmt.Sprintf("--audience=%s", annotationConfig.audience))
	}
	if annotationConfig.method == methodMetadata {
		cmd = append(cmd, "--use-metadata-server")
	}

	return corev1.Container{
		Name:            name,
		Image:           image,
		ImagePullPolicy: corev1.PullPolicy(pullPolicy),
		Command:         cmd,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      volumeName,
				MountPath: annotationConfig.volumePath,
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(requestsCPU),
				corev1.ResourceMemory: resource.MustParse(requestsMemory),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(limitsCPU),
				corev1.ResourceMemory: resource.MustParse(limitsMemory),
			},
		},
	}
}

func init() {
	logger = log.New()
	// set log level
	logger.SetLevel(log.WarnLevel)
	logger.SetFormatter(&log.TextFormatter{})
}

func before(c *cli.Context) error {
	// set debug log level
	switch level := c.GlobalString("log-level"); level {
	case "debug", "DEBUG":
		logger.SetLevel(log.DebugLevel)
	case "info", "INFO":
		logger.SetLevel(log.InfoLevel)
	case "warning", "WARNING":
		logger.SetLevel(log.WarnLevel)
	case "error", "ERROR":
		logger.SetLevel(log.ErrorLevel)
	case "fatal", "FATAL":
		logger.SetLevel(log.FatalLevel)
	case "panic", "PANIC":
		logger.SetLevel(log.PanicLevel)
	default:
		logger.SetLevel(log.WarnLevel)
	}
	// set log formatter to JSON
	if c.GlobalBool("json") {
		logger.SetFormatter(&log.JSONFormatter{})
	}
	return nil
}

func (mw *mutatingWebhook) podMutator(ctx context.Context, ar *whmodel.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	switch v := obj.(type) {
	case *corev1.Pod:
		err := mw.mutatePod(ctx, v, ar.Namespace, ar.DryRun)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to mutate pod: %s", v.Name)
		}
		return &mutating.MutatorResult{MutatedObject: v}, nil
	default:
		return &mutating.MutatorResult{}, nil
	}
}

// mutation webhook server
func runWebhook(c *cli.Context) error {
	k8sClient, err := newK8SClient()
	if err != nil {
		logger.WithError(err).Fatal("error creating k8s client")
	}

	webhook := mutatingWebhook{
		k8sClient:  k8sClient,
		image:      c.String("image"),
		pullPolicy: c.String("pull-policy"),
		volumeName: c.String("volume-name"),
		volumePath: c.String("volume-path"),
		tokenFile:  c.String("token-file"),
	}

	mutator := mutating.MutatorFunc(webhook.podMutator)
	metricsRecorder, err := metrics.NewRecorder(metrics.RecorderConfig{
		Registry: prometheus.DefaultRegisterer,
	})
	if err != nil {
		logger.WithError(err).Fatalf("error creating metrics recorder")
	}

	podHandler := handlerFor(
		mutating.WebhookConfig{
			ID:      "init-gtoken-pods",
			Obj:     &corev1.Pod{},
			Mutator: mutator,
			Logger:  whlogrus.NewLogrus(log.NewEntry(logger)),
		},
		metricsRecorder,
		logger,
	)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)
	mux.Handle("/healthz", http.HandlerFunc(healthzHandler))

	telemetryAddress := c.String("telemetry-listen-address")
	listenAddress := c.String("listen-address")
	tlsCertFile := c.String("tls-cert-file")
	tlsPrivateKeyFile := c.String("tls-private-key-file")

	if len(telemetryAddress) > 0 {
		// Serving metrics without TLS on separated address
		go serveMetrics(telemetryAddress)
	} else {
		mux.Handle("/metrics", promhttp.Handler())
	}

	if tlsCertFile == "" && tlsPrivateKeyFile == "" {
		logger.Infof("listening on http://%s", listenAddress)
		err = http.ListenAndServe(listenAddress, mux)
	} else {
		logger.Infof("listening on https://%s", listenAddress)
		err = http.ListenAndServeTLS(listenAddress, tlsCertFile, tlsPrivateKeyFile, mux)
	}

	if err != nil {
		logger.WithError(err).Fatal("error serving webhook")
	}

	return nil
}

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("version: %s\n", c.App.Version)
		fmt.Printf("  build date: %s\n", BuildDate)
		fmt.Printf("  built with: %s\n", runtime.Version())
	}
	app := cli.NewApp()
	app.Name = "gtoken-webhook"
	app.Version = Version
	app.Authors = []cli.Author{
		{
			Name:  "Alexei Ledenev",
			Email: "alexei.led@gmail.com",
		},
	}
	app.Usage = "gtoken-webhook is a Kubernetes mutation controller providing a secure access to AWS services from GKE pods"
	app.Before = before
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "log-level",
			Usage:  "set log level (debug, info, warning(*), error, fatal, panic)",
			Value:  "warning",
			EnvVar: "LOG_LEVEL",
		},
		cli.BoolFlag{
			Name:   "json",
			Usage:  "produce log in JSON format: Logstash and Splunk friendly",
			EnvVar: "LOG_JSON",
		},
	}
	app.Commands = []cli.Command{
		{
			Name: "server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "listen-address",
					Usage: "webhook server listen address",
					Value: ":8443",
				},
				cli.StringFlag{
					Name:  "telemetry-listen-address",
					Usage: "specify a dedicated prometheus metrics listen address (using listen-address, if empty)",
				},
				cli.StringFlag{
					Name:  "tls-cert-file",
					Usage: "TLS certificate file",
				},
				cli.StringFlag{
					Name:  "tls-private-key-file",
					Usage: "TLS private key file",
				},
				cli.StringFlag{
					Name:  "image",
					Usage: "Docker image with secrets-init utility on board",
					Value: gtokenInitImage,
				},
				cli.StringFlag{
					Name:  "pull-policy",
					Usage: "Docker image pull policy",
					Value: string(corev1.PullIfNotPresent),
				},
				cli.StringFlag{
					Name:  "volume-name",
					Usage: "mount volume name",
					Value: tokenVolumeName,
				},
				cli.StringFlag{
					Name:  "volume-path",
					Usage: "mount volume path",
					Value: tokenVolumePath,
				},
				cli.StringFlag{
					Name:  "token-file",
					Usage: "token file name",
					Value: tokenFileName,
				},
			},
			Usage:       "mutation admission webhook",
			Description: "run mutation admission webhook server",
			Action:      runWebhook,
		},
	}
	// print version in debug mode
	logger.WithField("version", app.Version).Debug("running gtoken-webhook")

	// run main command
	if err := app.Run(os.Args); err != nil {
		logger.Fatal(err)
	}
}
