using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using System.IdentityModel.Tokens.Jwt;
using AuthenticationApi.Helpers;
using Microsoft.Extensions.Options;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using AuthenticationApi.Services;
using AuthenticationApi.Entities;
using AuthenticationApi.Models.Users;

namespace AuthenticationApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public UsersController(
            IUserService userService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Login([FromBody] AuthenticateModel model)
        {
            var user = _userService.Authenticate(model.Username, model.Password);

            if (user == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString()),
                       new Claim(ClaimTypes.Role, user.UserType.ToString()),
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // return basic user info and authentication token
            return Ok(new
            {
                Id = user.Id,
                Username = user.Username,
                FirstName = user.FirstName,
                LastName = user.LastName,
                UserType=user.UserType,
                Token = tokenString
            });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register([FromBody] User model)
        {
            try
            {
                // create user
                if (model.UserType == UserType.Unknown)
                    model.UserType = UserType.Customer;
                _userService.Create(model);
                return Ok();
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet]
        [Authorize(Roles = "Administrator,Admin")]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            var model = _mapper.Map<IList<UserModel>>(users);
            return Ok(model);
        }

        [HttpGet("{id}")]
        public IActionResult GetById(long id)
        {
            var user = _userService.GetById(id);
            var currentuserId = long.Parse(User.Identity.Name);

            if (user == null)
                return NotFound();
            if (currentuserId != user.Id && !User.IsInRole(UserType.Administrator.ToString()))
                return Forbid();
            var model = _mapper.Map<UserModel>(user);
            return Ok(model);
        }

        [HttpPut]
        public IActionResult Update([FromBody] User model)
        {
            try
            {
                var user = _userService.GetById(model.Id);
                var currentuserId = long.Parse(User.Identity.Name);

                if (user == null)
                    return NotFound();
                if (currentuserId != model.Id && !User.IsInRole(UserType.Administrator.ToString()))
                    return Forbid();
                // update user 
                _userService.Update(model);
                return Ok();
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Administrator,Admin")]
        public IActionResult Delete(long id)
        {
            _userService.Delete(id);
            return Ok();
        }
    }
}