package fgbgp

import (
	log "github.com/sirupsen/logrus"
)

type Handler interface {
	Process(id int, msg interface{}) error
	Error(id int, msg interface{}, err error)
}

type Pool struct {
	Workers []*Worker
	Handler Handler
	inchan  chan chan interface{}
}

type Worker struct {
	Id      int
	Handler Handler
	inchan  chan chan interface{}
	inmsg   chan interface{}
	q       chan bool
}

func CreatePool(nworkers int, h Handler) *Pool {
	p := &Pool{
		Workers: make([]*Worker, nworkers),
		//inchan: make(chan chan interface{}, nworkers),
		inchan: make(chan chan interface{}),
	}
	for i := 0; i < nworkers; i++ {
		w := CreateWorker(i, h, p.inchan)
		p.Workers[i] = w
	}
	return p
}

func CreateWorker(id int, h Handler, inchan chan chan interface{}) *Worker {
	return &Worker{
		Id:      id,
		Handler: h,
		inchan:  inchan,
		inmsg:   make(chan interface{}),
		q:       make(chan bool),
	}
}

func (p *Pool) Start() {
	for i := range p.Workers {
		go p.Workers[i].Start()
	}
}
func (p *Pool) Stop() {
	for i := range p.Workers {
		go p.Workers[i].Stop()
	}
}

func (w *Worker) Start() {
	for {
		w.inchan <- w.inmsg
		select {
		case msg := <-w.inmsg:
			if w.Handler != nil {
				err := w.Handler.Process(w.Id, msg)
				if err != nil {
					log.Error(err)
					w.Handler.Error(w.Id, msg, err)
				}
			}
		case <-w.q:
			log.Infof("Stopping worker %v", w.Id)
			break
			break
		}
	}
}

func (w *Worker) Stop() {
	log.Infof("Stopping worker %v", w.Id)
	w.q <- true
}

func (p *Pool) Dispatch(msg interface{}) {
	inmsg := <-p.inchan
	inmsg <- msg
}
