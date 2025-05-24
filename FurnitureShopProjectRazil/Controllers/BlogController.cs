using Microsoft.AspNetCore.Mvc;

namespace FurnitureShopProjectRazil.Controllers
{
    public class BlogController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
