package jsonpb

import (
	"bytes"
	pb "github.com/gcash/bchutil/jsonpb/testpb"
	"testing"
)

var testMarshaledTransaction = `{
    "type": "UNCONFIRMED",
    "unconfirmedTransaction": {
        "addedHeight": 578547,
        "addedTime": 1555442269,
        "fee": 274,
        "feePerKb": 1007,
        "startingPriority": 233.78512396694214,
        "transaction": {
            "hash": "14e2ca55e5da7867799609092c66fe4d8f55d83f6035f85de00b89e7fb8102a4",
            "inputs": [
                {
                    "outpoint": {
                        "hash": "216817355c6a8f1b6d3ee139ad2c7c2c5700f6b2fd73249ea891f1d5025da3ad",
                        "index": 242
                    },
                    "sequence": 4294967295,
                    "signatureScript": "48304502210082beee6891f47370cce6c45f321c981fd26306550585f47d2d3493a7039c6d7102205bccf89f75187c74fcc8e2be1c182759b668635c4fcbb01b3dd2aff661e7982a41410467ff2df20f28bc62ad188525868f41d461f7dab3c1e500314cdb5218e5637bfd0f9c02eb5b3f383f698d28ff13547eaf05dd9216130861dd0216824e9d7337e3"
                }
            ],
            "outputs": [
                {
                    "disassembledScript": "OP_RETURN 5cb62a5c 45a2cc00378a946e3d7e5c923a8bc9cd3d0553263c81450f36b12adb3885ec94",
                    "pubkeyScript": "6a045cb62a5c2045a2cc00378a946e3d7e5c923a8bc9cd3d0553263c81450f36b12adb3885ec94"
                },
                {
                    "address": "qqrxa0h9jqnc7v4wmj9ysetsp3y7w9l36u8gnnjulq",
                    "disassembledScript": "OP_DUP OP_HASH160 066ebee590278f32aedc8a4865700c49e717f1d7 OP_EQUALVERIFY OP_CHECKSIG",
                    "index": 1,
                    "pubkeyScript": "76a914066ebee590278f32aedc8a4865700c49e717f1d788ac",
                    "scriptClass": "pubkeyhash",
                    "value": 3262
                }
            ],
            "size": 272,
            "version": 1
        }
    }
}`

func TestUnmarshalAndMarshall(t *testing.T) {
	tx := &pb.TransactionNotification{}
	if err := Unmarshal(bytes.NewReader([]byte(testMarshaledTransaction)), tx); err != nil {
		t.Fatal(err)
	}

	m := Marshaler{
		Indent: "    ",
	}
	s, err := m.MarshalToString(tx)
	if err != nil {
		t.Fatal(err)
	}
	if s != testMarshaledTransaction {
		t.Errorf("Failed to produce idential JSON")
	}
}
