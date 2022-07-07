#!/bin/bash


cwd=`pwd`
AS="$cwd/as"
RC="$cwd/rc"
RS="$cwd/rs"
API_TEST="$cwd/api-test"


start_stop() {
  if [[ $1 == "start" ]]; then
    start
  elif [[ $1 == "stop" ]]; then
   stop_all
  elif [[  $1 == "test" ]]; then
    test
  else
    echo "Usage setup.sh start | stop | test"
  fi

}

start() {
  stop_all;
  echo building everything
  mvn clean compile
  echo starting all servers!
  cd $AS
  mvn spring-boot:start
  cd $RC
  mvn spring-boot:start
  cd $RS
  mvn spring-boot:start

  cd $cwd
}

stop(){
  kill -15 $(cat $1/bin/shutdown.pid) 
}

test(){
  start
  cd $API_TEST
  echo running all api tests
  mvn clean test
  cd $cwd
  echo finished running tests!
  echo All servers are left running.....
}


stop_all(){
  echo stopping all servers!
  stop $AS
  stop $RC 
  stop $RS
 }

echo $1
start_stop $1



