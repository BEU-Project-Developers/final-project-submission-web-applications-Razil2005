using Microsoft.AspNetCore.Mvc;

namespace FurnitureShopProjectRazil.Controllers
{
    public class CheckoutController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
