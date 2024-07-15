package fox

import "encoding/json"

type Result struct {
	Data  string `json:"data"`
	Error string `json:"error"`
}

func jsonResult(data string, error string) string {
	res := Result{
		Data:  data,
		Error: error,
	}
	b, _ := json.Marshal(res)
	return string(b)
}

func Ok(data string) string {
	return jsonResult(data, "")
}

func Err(error error) string {
	return jsonResult("", error.Error())
}
