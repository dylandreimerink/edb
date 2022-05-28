package rangelist

import "encoding/binary"

type RangeListReader struct {
	data []byte
	bo   binary.ByteOrder
}

type Range struct {
	LowerPC uint64
	UpperPC uint64
}

func NewRangeListReader(data []byte) *RangeListReader {
	return &RangeListReader{
		data: data,
		bo:   binary.LittleEndian,
	}
}

func (rlr *RangeListReader) RangesAt(index int) ([]Range, error) {
	var ranges []Range

	for ; index+16 < len(rlr.data); index += 16 {
		r := Range{
			LowerPC: rlr.bo.Uint64(rlr.data[index : index+8]),
			UpperPC: rlr.bo.Uint64(rlr.data[index+8 : index+16]),
		}

		if r.LowerPC == 0 && r.UpperPC == 0 {
			break
		}

		ranges = append(ranges, r)
	}

	return ranges, nil
}
