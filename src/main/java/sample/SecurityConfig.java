/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import static java.util.Arrays.asList;

import boot.saml2.config.overridden.CustomOpenSamlAuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.time.Duration;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		CustomOpenSamlAuthenticationProvider authProvider = new CustomOpenSamlAuthenticationProvider();

//		OpenSamlAuthenticationProvider authProvider = new OpenSamlAuthenticationProvider();
		authProvider.setResponseTimeValidationSkew(Duration.ofMinutes(2));
//		authProvider.setAuthoritiesMapper(AUTHORITIES_MAPPER);
//		authProvider.setAuthoritiesExtractor(AUTHORITIES_EXTRACTOR);

		//@formatter:off
		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.saml2Login(saml2 -> saml2
				.authenticationManager(new ProviderManager(asList(authProvider)))
			)
		;
		//@formatter:on
	}

}
