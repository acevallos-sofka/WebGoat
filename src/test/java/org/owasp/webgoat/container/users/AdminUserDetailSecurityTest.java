/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.WebSecurityConfig;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.Course;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AdminController.class)
@ContextConfiguration(classes = {AdminController.class, WebSecurityConfig.class})
class AdminUserDetailSecurityTest {

  private static final String USER_DETAIL = "/service/admin/users/{username}";

  @Autowired private MockMvc mockMvc;
  @MockitoBean private UserService userService;
  @MockitoBean private UserProgressRepository userProgressRepository;
  @MockitoBean private Course course;
  @MockitoBean private PluginMessages pluginMessages;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  @Test
  void rejectsUnauthenticatedAjaxRequests() throws Exception {
    mockMvc
        .perform(get(USER_DETAIL, "testuser").header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());
    verifyNoInteractions(userService, userProgressRepository);
  }

  @Test
  @WithMockUser(authorities = "WEBGOAT_USER")
  void rejectsAuthenticatedUsersWithoutAdminAuthority() throws Exception {
    mockMvc.perform(get(USER_DETAIL, "testuser")).andExpect(status().isForbidden());
    verifyNoInteractions(userService, userProgressRepository);
  }

  @Test
  @WithMockUser(authorities = "WEBGOAT_ADMIN")
  void rejectsUsernamesLongerThan45CharactersBeforeLookup() throws Exception {
    mockMvc.perform(get(USER_DETAIL, "a".repeat(46))).andExpect(status().isBadRequest());
    verifyNoInteractions(userService, userProgressRepository);
  }

  @Test
  @WithMockUser(authorities = "WEBGOAT_ADMIN")
  void returnsAnEmptyNotFoundResponseForAnUnknownUser() throws Exception {
    when(userService.getAllUsers()).thenReturn(List.of());

    mockMvc
        .perform(get(USER_DETAIL, "a".repeat(45)))
        .andExpect(status().isNotFound())
        .andExpect(content().string(""));

    verify(userService).getAllUsers();
    verifyNoInteractions(userProgressRepository, course, pluginMessages);
  }
}
