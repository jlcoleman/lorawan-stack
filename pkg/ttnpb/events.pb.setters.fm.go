// Code generated by protoc-gen-fieldmask. DO NOT EDIT.

package ttnpb

import (
	fmt "fmt"
	time "time"
)

func (dst *Event) SetFields(src *Event, paths ...string) error {
	for name, subs := range _processPaths(append(paths[:0:0], paths...)) {
		switch name {
		case "name":
			if len(subs) > 0 {
				return fmt.Errorf("'name' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Name = src.Name
			} else {
				var zero string
				dst.Name = zero
			}
		case "time":
			if len(subs) > 0 {
				return fmt.Errorf("'time' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Time = src.Time
			} else {
				var zero time.Time
				dst.Time = zero
			}
		case "identifiers":
			if len(subs) > 0 {
				newDst := dst.Identifiers
				if newDst == nil {
					newDst = &CombinedIdentifiers{}
					dst.Identifiers = newDst
				}
				var newSrc *CombinedIdentifiers
				if src != nil {
					newSrc = src.Identifiers
				}
				if err := newDst.SetFields(newSrc, subs...); err != nil {
					return err
				}
			} else {
				if src != nil {
					dst.Identifiers = src.Identifiers
				} else {
					dst.Identifiers = nil
				}
			}
		case "data":
			if len(subs) > 0 {
				return fmt.Errorf("'data' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Data = src.Data
			} else {
				dst.Data = nil
			}
		case "correlation_ids":
			if len(subs) > 0 {
				return fmt.Errorf("'correlation_ids' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.CorrelationIDs = src.CorrelationIDs
			} else {
				dst.CorrelationIDs = nil
			}
		case "origin":
			if len(subs) > 0 {
				return fmt.Errorf("'origin' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Origin = src.Origin
			} else {
				var zero string
				dst.Origin = zero
			}
		case "context":
			if len(subs) > 0 {
				return fmt.Errorf("'context' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Context = src.Context
			} else {
				dst.Context = nil
			}

		default:
			return fmt.Errorf("invalid field: '%s'", name)
		}
	}
	return nil
}

func (dst *StreamEventsRequest) SetFields(src *StreamEventsRequest, paths ...string) error {
	for name, subs := range _processPaths(append(paths[:0:0], paths...)) {
		switch name {
		case "identifiers":
			if len(subs) > 0 {
				newDst := &dst.Identifiers
				var newSrc *CombinedIdentifiers
				if src != nil {
					newSrc = &src.Identifiers
				}
				if err := newDst.SetFields(newSrc, subs...); err != nil {
					return err
				}
			} else {
				if src != nil {
					dst.Identifiers = src.Identifiers
				} else {
					var zero CombinedIdentifiers
					dst.Identifiers = zero
				}
			}
		case "tail":
			if len(subs) > 0 {
				return fmt.Errorf("'tail' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.Tail = src.Tail
			} else {
				var zero uint32
				dst.Tail = zero
			}
		case "after":
			if len(subs) > 0 {
				return fmt.Errorf("'after' has no subfields, but %s were specified", subs)
			}
			if src != nil {
				dst.After = src.After
			} else {
				dst.After = nil
			}

		default:
			return fmt.Errorf("invalid field: '%s'", name)
		}
	}
	return nil
}
