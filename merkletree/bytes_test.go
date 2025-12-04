package merkletree

import (
	"testing"
)

func TestToBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   BytesLike
		want    []byte
		wantErr bool
	}{
		{
			name:    "byte array",
			input:   []byte{1, 2, 3, 4},
			want:    []byte{1, 2, 3, 4},
			wantErr: false,
		},
		{
			name:    "hex string with 0x prefix",
			input:   "0x48656c6c6f",
			want:    []byte("Hello"),
			wantErr: false,
		},
		{
			name:    "HexString type",
			input:   HexString("0x48656c6c6f"),
			want:    []byte("Hello"),
			wantErr: false,
		},
		{
			name:    "regular string",
			input:   "Hello",
			want:    []byte("Hello"),
			wantErr: false,
		},
		{
			name:    "int array",
			input:   []int{72, 101, 108, 108, 111},
			want:    []byte("Hello"),
			wantErr: false,
		},
		{
			name:    "invalid hex string",
			input:   "0xGGGG",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if string(got) != string(tt.want) {
					t.Errorf("ToBytes() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestToHex(t *testing.T) {
	tests := []struct {
		name    string
		input   BytesLike
		want    HexString
		wantErr bool
	}{
		{
			name:    "byte array",
			input:   []byte("Hello"),
			want:    HexString("0x48656c6c6f"),
			wantErr: false,
		},
		{
			name:    "hex string",
			input:   "0x48656c6c6f",
			want:    HexString("0x48656c6c6f"),
			wantErr: false,
		},
		{
			name:    "HexString type",
			input:   HexString("0x48656c6c6f"),
			want:    HexString("0x48656c6c6f"),
			wantErr: false,
		},
		{
			name:    "int array",
			input:   []int{72, 101, 108, 108, 111},
			want:    HexString("0x48656c6c6f"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToHex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToHex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ToHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConcat(t *testing.T) {
	tests := []struct {
		name    string
		inputs  []BytesLike
		want    []byte
		wantErr bool
	}{
		{
			name:    "two byte arrays",
			inputs:  []BytesLike{[]byte("Hello"), []byte(" World")},
			want:    []byte("Hello World"),
			wantErr: false,
		},
		{
			name:    "mixed types",
			inputs:  []BytesLike{[]byte("Hello"), "0x20", []byte("World")},
			want:    []byte("Hello World"),
			wantErr: false,
		},
		{
			name:    "single value",
			inputs:  []BytesLike{[]byte("Hello")},
			want:    []byte("Hello"),
			wantErr: false,
		},
		{
			name:    "empty",
			inputs:  []BytesLike{},
			want:    []byte{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Concat(tt.inputs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Concat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if string(got) != string(tt.want) {
					t.Errorf("Concat() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name    string
		a       BytesLike
		b       BytesLike
		want    int
		wantErr bool
	}{
		{
			name:    "a < b",
			a:       "0x1111",
			b:       "0x2222",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "a == b",
			a:       "0x1111",
			b:       "0x1111",
			want:    0,
			wantErr: false,
		},
		{
			name:    "a > b",
			a:       "0x2222",
			b:       "0x1111",
			want:    1,
			wantErr: false,
		},
		{
			name:    "byte arrays",
			a:       []byte{0x11, 0x11},
			b:       []byte{0x22, 0x22},
			want:    -1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compare(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
