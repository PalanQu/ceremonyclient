package store

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

type PebbleDB struct {
	config *config.DBConfig
	db     *pebble.DB
}

func NewPebbleDB(config *config.DBConfig) *PebbleDB {
	db, err := pebble.Open(config.Path, &pebble.Options{})
	if err != nil {
		panic(err)
	}

	return &PebbleDB{config, db}
}

func (p *PebbleDB) Get(key []byte) ([]byte, io.Closer, error) {
	return p.db.Get(key)
}

func (p *PebbleDB) Set(key, value []byte) error {
	return p.db.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) NewBatch(indexed bool) Transaction {
	if indexed {
		return &PebbleTransaction{
			b: p.db.NewIndexedBatch(),
		}
	} else {
		return &PebbleTransaction{
			b: p.db.NewBatch(),
		}
	}
}

func (p *PebbleDB) NewOversizedBatch() Transaction {
	path := path.Join(
		p.config.Path,
		fmt.Sprintf("batch-%d", time.Now().UnixMilli()),
	)

	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		panic(err)
	}

	return &PebbleIngestTransaction{
		path:   path,
		parent: p.db,
		b:      db,
	}
}

func (p *PebbleDB) NewIter(lowerBound []byte, upperBound []byte) (
	Iterator,
	error,
) {
	return p.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (p *PebbleDB) Compact(start, end []byte, parallelize bool) error {
	return p.db.Compact(start, end, parallelize)
}

func (p *PebbleDB) Close() error {
	return p.db.Close()
}

func (p *PebbleDB) DeleteRange(start, end []byte) error {
	return p.db.DeleteRange(start, end, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) CompactAll() error {
	iter, err := p.db.NewIter(nil)
	if err != nil {
		return errors.Wrap(err, "compact all")
	}

	var first, last []byte
	if iter.First() {
		first = append(first, iter.Key()...)
	}
	if iter.Last() {
		last = append(last, iter.Key()...)
	}
	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "compact all")
	}

	if err := p.Compact(first, last, false); err != nil {
		return errors.Wrap(err, "compact all")
	}

	return nil
}

var _ KVDB = (*PebbleDB)(nil)

type Transaction interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key []byte, value []byte) error
	Commit() error
	Delete(key []byte) error
	Abort() error
	NewIter(lowerBound []byte, upperBound []byte) (Iterator, error)
	DeleteRange(lowerBound []byte, upperBound []byte) error
}

type PebbleIngestTransaction struct {
	path   string
	parent *pebble.DB
	b      *pebble.DB
}

func (t *PebbleIngestTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return t.b.Get(key)
}

func (t *PebbleIngestTransaction) Set(key []byte, value []byte) error {
	return t.b.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleIngestTransaction) Commit() error {
	t.b.Close()
	find := func(root, ext string) []string {
		var a []string
		filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if filepath.Ext(d.Name()) == ext {
				a = append(a, s)
			}
			return nil
		})
		return a
	}

	err := t.parent.Ingest(find(t.path, ".sst"))
	if err != nil {
		return errors.Wrap(err, "commit")
	}

	wait, err := t.parent.AsyncFlush()
	if err != nil {
		return errors.Wrap(err, "commit")
	}

	<-wait
	return nil
}

func (t *PebbleIngestTransaction) Delete(key []byte) error {
	return t.b.Delete(key, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleIngestTransaction) Abort() error {
	t.b.Close()
	return errors.Wrap(os.RemoveAll(t.path), "abort")
}

func (t *PebbleIngestTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	Iterator,
	error,
) {
	return nil, errors.New("unsupported")
}

func (t *PebbleIngestTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return errors.New("unsupported")
}

type PebbleTransaction struct {
	b *pebble.Batch
}

func (t *PebbleTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return t.b.Get(key)
}

func (t *PebbleTransaction) Set(key []byte, value []byte) error {
	return t.b.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Commit() error {
	return t.b.Commit(&pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Delete(key []byte) error {
	return t.b.Delete(key, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Abort() error {
	return t.b.Close()
}

func (t *PebbleTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	Iterator,
	error,
) {
	return t.b.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (t *PebbleTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return t.b.DeleteRange(
		lowerBound,
		upperBound,
		&pebble.WriteOptions{Sync: true},
	)
}

var _ Transaction = (*PebbleTransaction)(nil)
var _ Transaction = (*PebbleIngestTransaction)(nil)

func rightAlign(data []byte, size int) []byte {
	l := len(data)

	if l == size {
		return data
	}

	if l > size {
		return data[l-size:]
	}

	pad := make([]byte, size)
	copy(pad[size-l:], data)
	return pad
}
