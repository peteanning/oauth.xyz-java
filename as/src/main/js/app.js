import React from 'react';

import ReactDOM from 'react-dom';
import http from './http';
import { Button, Badge, Row, Col, Container, Card, CardImg, CardText, CardBody, CardTitle, CardSubtitle, CardHeader, Input } from 'reactstrap';
import { BrowserRouter, Switch, Route } from 'react-router-dom';

import AuthServer from './authserver';
import Client from './client';
import Interact from './interact';
import SPA from './spa';

ReactDOM.render((
	<BrowserRouter>
		<Switch>
			<Route path='/interact' component={Interact} />
			<Route path='/as' component={AuthServer} />
		</Switch>
	</BrowserRouter>
	),
	document.getElementById('react')
);
