/*
 * Copyright (C) 2022 Lenovo
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 * This is the implmentation of client input data checking and formating methods
 */

package util

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gotomicro/ego/core/elog"
	"github.com/ipipdotnet/ipdb-go"
)

const (
	DOTS           = 3
	VER_SEG_MAXLEN = 5
	SHORT_LEN      = 40
	MID_LEN        = 500
	MAIL_LEN       = 1000
	LONG_LEN       = 4000
	PARAM_LEN      = 10000
	TIME_LAYOUT    = "2006-01-02 15:04:05"
)

var ipDB *ipdb.City

func GenerateKid() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits

	kid := hex.EncodeToString(b)
	return kid, nil
}

// version naming conversion:
// 11.22.33.MMDD3 (MM: month, ex. 01, 10; DD: day of month, ex. 01, 11, 25, 31; 3: the 3rd version of that day)
// with the following restriction
// 1. version contains only '.' and number
// 2. 7 <= length <= 23
// 3. the first number must > 0
// 4. must have 3 '.'
func ValidVersion(ver string) bool {
	var dotNum int = 0
	// 1. 7 <= length <= 23
	if len(ver) < 7 || len(ver) > 23 {
		return false
	}
	// 2. strings should only contains the digit and seperated by '.'
	for _, char := range ver {
		if char == '.' {
			dotNum++
		} else if !unicode.IsDigit(char) {
			return false
		}
	}

	// 3. version seperated by '.', and splitted version segment should not longer than 5
	verStrings := strings.Split(ver, ".")
	for _, splittedVer := range verStrings {
		if len(splittedVer) > VER_SEG_MAXLEN {
			return false
		}
	}

	// 4. must have 3 '.'
	return dotNum == DOTS
}

// format the version to the unified xxxxx.xxxxx.xxxxx.xxxxx, ex. 2.5.8.8302->00002000050000808302
// we cannot simply pass through the version string to database becase we have to do backward compatible :
// in old client there is 1.0.0.9311 (should be 1.0.0.09311) which is bigger than
// 1.0.0.10021 (incorrect, because 9311 means Sep.31 the 1st version) in string sort algorithm
func FormatVersion(ver string) string {
	if len(ver) == 0 {
		return ""
	}
	var formattedString string = ""
	verStrings := strings.Split(ver, ".")
	if len(verStrings) < 4 {
		num := 4 - len(verStrings)
		for i := 0; i < num; i++ {
			verStrings = append(verStrings, "0")
		}
	}
	for i, splittedVer := range verStrings {
		// we do not record the strconv error because validVersion() filtered the strings which contains none digit characters
		verNum, err := strconv.Atoi(splittedVer)
		if err != nil {
			elog.Error("Data type switching error")
		}
		tmpStr := fmt.Sprintf("%05d", verNum)
		formattedString += tmpStr
		if i < DOTS {
			formattedString += "."
		} else {
			break
		}
	}

	return formattedString
}

func FormatOffVersion(ver string) string {
	if len(ver) == 0 {
		return ""
	}
	parts := strings.Split(ver, ".")
	var simplifiedParts []string

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			fmt.Println("Error converting string to int:", err)
			return ""
		}
		if !(len(simplifiedParts) == 0 && num == 0) {
			// 仅在非首部分为0时省略
			simplifiedParts = append(simplifiedParts, strconv.Itoa(num))
		}
	}
	if len(simplifiedParts) == 0 {
		return "0"
	}

	return strings.Join(simplifiedParts, ".")
}

// limit the str into 'length', if 'groom', also change the str to lower case and replace ' ' to '_'
func FormatString(str string, length int, groom bool) string {
	// we are facing the threat that malicious attacks ota server by randomly send garbage data
	// to server which trigger the ota server to cache it, then our redis size will be quickly goes up and out of functional
	// because we create cache in redis by using the client input channel, mt, os, ... info
	// that why we must limit the info length before use
	if len(str) == 0 {
		return ""
	}
	if length > 0 && len(str) > length {
		str = str[0:length]
	}

	if groom {
		elog.Error("str1=========" + strings.Replace(strings.Replace(strings.ToLower(str), " ", "_", -1), "-", "_", -1))
		// format conversion tmpporary adjustment
		return strings.Replace(strings.Replace(strings.ToLower(str), " ", "_", -1), "-", "_", -1)
	} else {
		elog.Error("str2=========" + str)
		return str
	}
}

func FormatStrings(strs []string, length int, groom bool) []string {
	var returnStrs []string
	for _, str := range strs {
		returnStrs = append(returnStrs, FormatString(str, length, groom))
	}
	return returnStrs
}

// format the data from human readable date time to unix integer time
func StrToUnixTime(str string) int64 {
	if t, err := time.Parse(TIME_LAYOUT, str); err != nil {
		return 0
	} else {
		return t.Unix()
	}
}

// format the data from unix integer time to human readable date time
func UnixTimeToStr(t int64) string {
	if t == 0 {
		return ""
	} else {
		var cstZone = time.FixedZone("GMT", 8*3600) // 东八
		return time.Unix(t, 0).In(cstZone).Format(TIME_LAYOUT)
	}
}

func Map2Region(ip string) string {
	if ipDB == nil {
		err := ipdbInit("./data/ipdb/ipip_20200617.ipdb")
		if err != nil {
			return ""
		}
	}
	cityInfo, err := ipDB.FindInfo(ip, "CN")
	if err != nil {
		return ""
	}

	return cityInfo.CountryName
	/*
		 if cityInfo.CountryCode == "CN" {
			 return cityInfo.RegionName // if the ip is from China, returns province name, like "天津"
		 } else {
			 return cityInfo.CountryName // else just return the contry name, because the current database doesn't contain ROW province info
		 }
	*/
}

func PasswordGenerate(length int) string {
	baseStr := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}+-*/_=."
	r := rand.New(rand.NewSource(time.Now().UnixNano() + rand.Int63()))
	bytes := make([]byte, length)
	l := len(baseStr)
	for i := 0; i < length; i++ {
		bytes[i] = baseStr[r.Intn(l)]
	}
	return string(bytes)
}

// isEmailValid checks if the email provided is valid by regex.
func EmailIsValid(e string) bool {
	emailRegex := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return emailRegex.MatchString(e)
}

func ipdbInit(dbPath string) error {
	var err error
	ipDB, err = ipdb.NewCity(dbPath)
	if err != nil {
		elog.Panic("init ip database error with err msg: " + err.Error())
		return err
	}

	return nil
}

func GenerateRandomFileName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	fileName := make([]byte, length)
	for i := range fileName {
		fileName[i] = charset[rand.Intn(len(charset))]
	}
	return string(fileName)
}
