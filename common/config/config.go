package config

import (
	"flag"
	"fmt"
	"strings"

	//"io/ioutil"
	"gopkg.in/yaml.v2"
	"os"
)

type config struct {
	Server        server        `yaml:"server"`
	DB            db            `yaml:"db"`
	Redis         redis         `yaml:"redis"`
	Log           log           `yaml:"log"`
	ImageSettings imageSettings `yaml:"imageSettings"`
}
type server struct {
	Address string `yaml:"address"`
	Model   string `yaml:"model"`
}

// 数据库配置
type db struct {
	Dialects string `yaml:"dialects"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Name     string `yaml:"db"`
	//DB       string `yaml:"db"`
	Charset string `yaml:"charset"`
	MaxIdle int    `yaml:"maxIdle"`
	MaxOpen int    `yaml:"maxOpen"`
}

// redis settings
type redis struct {
	Address  string `yaml:"address"`
	Port     string `yaml:"port"`
	Password string `yaml:"password"`
}

// picture settings
type imageSettings struct {
	UploadDir string `yaml:"uploadDir"`
	ImageHost string `yaml:"imageHost"`
}

// log settings
type log struct {
	Path  string `yaml:"path"`
	Name  string `yaml:"name"`
	Model string `yaml:"model"`
}

var Config *config

// 读取配置文件并动态替换占位符
func parseConfigWithEnv(filePath string) error {
	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// 将内容转换为字符串
	configStr := string(content)

	// 替换占位符为环境变量值
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			placeholder := fmt.Sprintf("{%s}", parts[0]) // {ENV_VAR}
			configStr = strings.ReplaceAll(configStr, placeholder, parts[1])
		}
	}

	// 解析 YAML 内容到 map
	//var config map[string]interface{}
	err = yaml.Unmarshal([]byte(configStr), &Config)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	return nil
}

//func LoadConfig(configPath string) {
//	file, err := os.ReadFile(configPath)
//	if err != nil {
//		panic(err)
//	}
//	err1 := yaml.Unmarshal(file, &Config)
//	if err1 != nil {
//		panic(err1)
//	}
//}

func init() {
	configPath := flag.String("config", "config_dev.yaml", "path to the config file")
	flag.Parse()
	//LoadConfig(*configPath)
	err := parseConfigWithEnv(*configPath)
	if err != nil {
		panic(err)
	}
}
